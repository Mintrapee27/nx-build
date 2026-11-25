import argparse
import bisect
import struct
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Util import Counter


def align_up(val: int, align: int) -> int:
    return (val + align - 1) & ~(align - 1)


def load_keys(keys_path: Path) -> dict[str, bytes]:
    keys = {}
    for line in keys_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip().lower()
        v = v.strip().replace(" ", "")
        try:
            keys[k] = bytes.fromhex(v)
        except ValueError:
            pass
    return keys


def aes_xts_decrypt(data: bytes, header_key: bytes, sector_size: int = 0x200) -> bytes:
    key1 = header_key[:16]
    key2 = header_key[16:32]
    ecb1 = AES.new(key1, AES.MODE_ECB)
    ecb2 = AES.new(key2, AES.MODE_ECB)
    out = bytearray(len(data))
    num_sectors = len(data) // sector_size

    for s in range(num_sectors):
        tweak = s.to_bytes(16, "big")
        T = ecb2.encrypt(tweak)
        t_int = int.from_bytes(T, "little")
        s_off = s * sector_size
        for b in range(0, sector_size, 16):
            off = s_off + b
            t_bytes = t_int.to_bytes(16, "little")
            xored = bytes(x ^ y for x, y in zip(data[off : off + 16], t_bytes))
            dec = ecb1.decrypt(xored)
            out[off : off + 16] = bytes(x ^ y for x, y in zip(dec, t_bytes))
            carry = (t_int >> 127) & 1
            t_int = ((t_int << 1) ^ (0x87 if carry else 0)) & ((1 << 128) - 1)

    return bytes(out)


def unpack_pfs0(nsp_path: Path, out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    extracted = []
    with open(nsp_path, "rb") as f:
        hdr = f.read(0x10)
        magic, num_files, str_table_size, _ = struct.unpack("<4sIII", hdr)
        if magic != b"PFS0":
            raise ValueError(f"Not a valid PFS0/NSP file: {nsp_path}")
        entries_raw = f.read(num_files * 0x18)
        str_table = f.read(str_table_size)
        data_base = 0x10 + num_files * 0x18 + str_table_size

        for i in range(num_files):
            d_off, d_size, s_off, _ = struct.unpack_from("<QQII", entries_raw, i * 0x18)
            end_str = str_table.find(b"\x00", s_off)
            name = str_table[s_off:end_str].decode("utf-8")
            dst = out_dir / name
            f.seek(data_base + d_off)
            rem = d_size
            with open(dst, "wb") as out_f:
                while rem > 0:
                    chunk = f.read(min(rem, 4 * 1024 * 1024))
                    if not chunk:
                        break
                    out_f.write(chunk)
                    rem -= len(chunk)
            extracted.append(dst)
    return extracted


def collect_title_keys(nca_dir: Path, keys: dict[str, bytes]) -> dict[bytes, bytes]:
    tik_keys = {}
    for tik in nca_dir.glob("*.tik"):
        raw = tik.read_bytes()
        if len(raw) >= 0x2B0:
            enc_tkey = raw[0x180:0x190]
            rights_id = raw[0x2A0:0x2B0]
            tik_keys[rights_id] = enc_tkey
    return tik_keys


class NcaReader:
    def __init__(self, nca_path: Path, keys: dict[str, bytes], tik_keys: dict[bytes, bytes], base_nca=None):
        self.path = nca_path
        self.keys = keys
        self.base_nca = base_nca
        self.fp = open(nca_path, "rb")

        enc_hdr = self.fp.read(0xC00)
        hdr = aes_xts_decrypt(enc_hdr, keys["header_key"], 0x200)
        if hdr[0x200:0x204] not in (b"NCA3", b"NCA2"):
            raise ValueError(f"Failed to decrypt NCA header: {nca_path}")

        self.content_type = hdr[0x205]
        self.title_id = f"{struct.unpack_from('<Q', hdr, 0x210)[0]:016x}"
        rev = max(hdr[0x206], hdr[0x220])
        if rev > 0:
            rev -= 1
        rev_hex = f"{rev:02x}"

        rights_id = hdr[0x230:0x240]
        if rights_id != b"\x00" * 16:
            if rights_id not in tik_keys:
                raise KeyError(f"Missing ticket for rights_id {rights_id.hex()}")
            tkey_enc = tik_keys[rights_id]
            self.ctr_key = AES.new(keys[f"titlekek_{rev_hex}"], AES.MODE_ECB).decrypt(tkey_enc)
        else:
            kaek_type = ["application", "ocean", "system"][hdr[0x207]]
            kaek = keys[f"key_area_key_{kaek_type}_{rev_hex}"]
            self.ctr_key = AES.new(kaek, AES.MODE_ECB).decrypt(hdr[0x320:0x330])

        self.sections = []
        for i in range(4):
            m_start, m_end, enabled = struct.unpack_from("<IIB", hdr, 0x240 + i * 0x10)
            fs_hdr = hdr[0x400 + i * 0x200 : 0x600 + i * 0x200]
            self.sections.append(
                {
                    "enabled": bool(enabled),
                    "start": m_start * 0x200,
                    "end": m_end * 0x200,
                    "fs_hdr": fs_hdr,
                    "fs_type": fs_hdr[0x02],
                    "enc_type": fs_hdr[0x04],
                    "iv_prefix": fs_hdr[0x140:0x148][::-1],
                }
            )

        self.reloc_entries = []
        self.reloc_starts = []
        self.subsec_entries = []
        self.subsec_starts = []

        if self.content_type == 0 and len(self.sections) > 1 and self.sections[1]["enabled"]:
            sec1 = self.sections[1]
            if sec1["enc_type"] == 4:
                self._init_bktr(sec1)

    def _init_bktr(self, sec1: dict):
        fs_hdr = sec1["fs_hdr"]
        reloc_off, reloc_size = struct.unpack_from("<QQ", fs_hdr, 0x100)
        subsec_off, subsec_size = struct.unpack_from("<QQ", fs_hdr, 0x120)

        reloc_raw = self.read_ctr(sec1["start"] + reloc_off, reloc_size, sec1["iv_prefix"])
        _, num_buckets, _ = struct.unpack_from("<IIQ", reloc_raw, 0x00)
        for b in range(num_buckets):
            b_off = 0x4000 + b * 0x4000
            _, num_entries, _ = struct.unpack_from("<IIQ", reloc_raw, b_off)
            for e in range(num_entries):
                e_off = b_off + 0x10 + e * 0x14
                v_off, p_off, is_patch = struct.unpack_from("<QQI", reloc_raw, e_off)
                self.reloc_entries.append((v_off, p_off, is_patch))
                self.reloc_starts.append(v_off)

        subsec_raw = self.read_ctr(sec1["start"] + subsec_off, subsec_size, sec1["iv_prefix"])
        _, s_buckets, _ = struct.unpack_from("<IIQ", subsec_raw, 0x00)
        for b in range(s_buckets):
            b_off = 0x4000 + b * 0x4000
            _, num_entries, _ = struct.unpack_from("<IIQ", subsec_raw, b_off)
            for e in range(num_entries):
                e_off = b_off + 0x10 + e * 0x10
                sv_off, _, s_ctr = struct.unpack_from("<QII", subsec_raw, e_off)
                self.subsec_entries.append((sv_off, s_ctr))
                self.subsec_starts.append(sv_off)

    def read_ctr(self, nca_offset: int, length: int, iv_prefix: bytes) -> bytes:
        if length <= 0:
            return b""
        aligned_off = nca_offset & ~0xF
        skip = nca_offset - aligned_off
        aligned_len = align_up(skip + length, 16)
        self.fp.seek(aligned_off)
        raw = self.fp.read(aligned_len)
        ctr = Counter.new(64, prefix=iv_prefix, initial_value=(aligned_off >> 4), little_endian=False)
        dec = AES.new(self.ctr_key, AES.MODE_CTR, counter=ctr).decrypt(raw)
        return dec[skip : skip + length]

    def read_sec0(self, rel_offset: int, length: int) -> bytes:
        sec0 = self.sections[0]
        if sec0["enc_type"] == 1:
            self.fp.seek(sec0["start"] + rel_offset)
            return self.fp.read(length)
        return self.read_ctr(sec0["start"] + rel_offset, length, sec0["iv_prefix"])

    def read_sec1(self, rel_offset: int, length: int) -> bytes:
        sec1 = self.sections[1]
        if sec1["enc_type"] == 1:
            self.fp.seek(sec1["start"] + rel_offset)
            return self.fp.read(length)
        if sec1["enc_type"] == 3:
            return self.read_ctr(sec1["start"] + rel_offset, length, sec1["iv_prefix"])
        if sec1["enc_type"] == 4:
            out = bytearray()
            cur = rel_offset
            end = rel_offset + length
            while cur < end:
                idx = bisect.bisect_right(self.reloc_starts, cur) - 1
                v_off, p_off, is_patch = self.reloc_entries[idx]
                next_v = self.reloc_entries[idx + 1][0] if idx + 1 < len(self.reloc_entries) else end
                step = min(end - cur, next_v - cur)
                delta = cur - v_off
                if is_patch == 0:
                    out.extend(self.base_nca.read_sec1(p_off + delta, step))
                else:
                    phys = p_off + delta
                    s_idx = bisect.bisect_right(self.subsec_starts, phys) - 1
                    _, s_ctr = self.subsec_entries[s_idx]
                    custom_iv = struct.pack(">I", s_ctr) + sec1["iv_prefix"][4:8]
                    out.extend(self.read_ctr(sec1["start"] + phys, step, custom_iv))
                cur += step
            return bytes(out)
        raise ValueError(f"Unsupported encryption type: {sec1['enc_type']}")

    def extract_exefs(self, out_dir: Path):
        out_dir.mkdir(parents=True, exist_ok=True)
        fs_hdr0 = self.sections[0]["fs_hdr"]
        pfs0_off, pfs0_size = struct.unpack_from("<QQ", fs_hdr0, 0x48)
        pfs0 = self.read_sec0(pfs0_off, pfs0_size)
        _, num_files, str_size, _ = struct.unpack_from("<4sIII", pfs0, 0x00)
        str_base = 0x10 + num_files * 0x18
        data_base = str_base + str_size
        for i in range(num_files):
            d_off, d_size, s_off, _ = struct.unpack_from("<QQII", pfs0, 0x10 + i * 0x18)
            end_s = pfs0.find(b"\x00", str_base + s_off)
            name = pfs0[str_base + s_off : end_s].decode("utf-8")
            (out_dir / name).write_bytes(pfs0[data_base + d_off : data_base + d_off + d_size])

    def extract_romfs(self, out_dir: Path):
        out_dir.mkdir(parents=True, exist_ok=True)
        fs_hdr1 = self.sections[1]["fs_hdr"]
        romfs_off, _ = struct.unpack_from("<QQ", fs_hdr1, 0xA8)
        hdr = self.read_sec1(romfs_off, 0x50)
        _, dir_hash_off, dir_hash_sz, dir_meta_off, dir_meta_sz, _, _, file_meta_off, file_meta_sz, data_off = struct.unpack(
            "<QQQQQQQQQQ", hdr
        )
        dir_meta = self.read_sec1(romfs_off + dir_meta_off, dir_meta_sz)
        file_meta = self.read_sec1(romfs_off + file_meta_off, file_meta_sz)

        def walk_dir(d_off: int, parent_path: Path):
            _, sibling, c_dir, c_file, _, name_len = struct.unpack_from("<IIIIII", dir_meta, d_off)
            name = dir_meta[d_off + 0x18 : d_off + 0x18 + name_len].decode("utf-8")
            cur_dir = parent_path / name if name else parent_path
            cur_dir.mkdir(parents=True, exist_ok=True)

            f_off = c_file
            while f_off != 0xFFFFFFFF:
                _, f_sib, f_doff, f_sz, _, f_nlen = struct.unpack_from("<IIQQII", file_meta, f_off)
                f_name = file_meta[f_off + 0x20 : f_off + 0x20 + f_nlen].decode("utf-8")
                dst_file = cur_dir / f_name
                rem = f_sz
                pos = romfs_off + data_off + f_doff
                with open(dst_file, "wb") as out_f:
                    while rem > 0:
                        step = min(rem, 4 * 1024 * 1024)
                        out_f.write(self.read_sec1(pos, step))
                        pos += step
                        rem -= step
                f_off = f_sib

            sub_d = c_dir
            while sub_d != 0xFFFFFFFF:
                walk_dir(sub_d, cur_dir)
                sub_d = struct.unpack_from("<I", dir_meta, sub_d + 4)[0]

        walk_dir(0, out_dir)

    def close(self):
        self.fp.close()


def find_program_nca(nca_dir: Path, keys: dict[str, bytes], tik_keys: dict[bytes, bytes], base_nca=None) -> NcaReader:
    candidates = sorted(nca_dir.glob("*.nca"), key=lambda p: p.stat().st_size, reverse=True)
    for p in candidates:
        try:
            reader = NcaReader(p, keys, tik_keys, base_nca=base_nca)
            if reader.content_type == 0:
                return reader
            reader.close()
        except Exception:
            continue
    raise RuntimeError(f"No Program NCA found in {nca_dir}")


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)

    ext = sub.add_parser("extract")
    ext.add_argument("--keys", required=True)
    ext.add_argument("--base-nsp", required=True)
    ext.add_argument("--update-nsp", default="")
    ext.add_argument("--base-nca-dir", required=True)
    ext.add_argument("--upd-nca-dir", required=True)
    ext.add_argument("--exefs", required=True)
    ext.add_argument("--romfs", required=True)
    ext.add_argument("--info-out", required=True)

    ver = sub.add_parser("verify")
    ver.add_argument("--nsp", required=True)

    args = parser.parse_args()

    if args.cmd == "verify":
        p = Path(args.nsp)
        with open(p, "rb") as f:
            magic, num_files, _, _ = struct.unpack("<4sIII", f.read(0x10))
        if magic != b"PFS0" or num_files == 0:
            raise ValueError("Invalid NSP output")
        print(f"Verified NSP successfully: {p.name} ({num_files} NCAs, {p.stat().st_size / (1024*1024):.1f} MB)")
        return

    keys = load_keys(Path(args.keys))
    base_dir = Path(args.base_nca_dir)
    unpack_pfs0(Path(args.base_nsp), base_dir)
    base_tiks = collect_title_keys(base_dir, keys)
    base_prog = find_program_nca(base_dir, keys, base_tiks)

    active_prog = base_prog
    src_nca_dir = base_dir

    if args.update_nsp and Path(args.update_nsp).exists():
        upd_dir = Path(args.upd_nca_dir)
        unpack_pfs0(Path(args.update_nsp), upd_dir)
        upd_tiks = {**base_tiks, **collect_title_keys(upd_dir, keys)}
        active_prog = find_program_nca(upd_dir, keys, upd_tiks, base_nca=base_prog)
        src_nca_dir = upd_dir

    print(f"Extracting ExeFS and RomFS from {active_prog.path.name} (Title ID: {active_prog.title_id})...")
    active_prog.extract_exefs(Path(args.exefs))
    active_prog.extract_romfs(Path(args.romfs))

    info_text = (
        f"TITLE_ID={active_prog.title_id}\n"
        f"PROG_NAME={active_prog.path.name}\n"
        f"SRC_NCA_DIR={src_nca_dir.as_posix()}\n"
    )
    Path(args.info_out).write_text(info_text, encoding="utf-8")
    print(info_text.strip())

    if active_prog is not base_prog:
        active_prog.close()
    base_prog.close()


if __name__ == "__main__":
    main()
