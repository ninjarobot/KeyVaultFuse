namespace KeyVaultFuse

open System
open System.Runtime.InteropServices

module Libc =
    [<DllImport("libc", EntryPoint = "memset", CallingConvention = CallingConvention.Cdecl)>]
    extern void memset(IntPtr ptr, int value, int64 num)
    [<DllImport("libc", EntryPoint = "getuid", CallingConvention = CallingConvention.Cdecl)>]
    extern uint getuid()
    [<DllImport("libc", EntryPoint = "getgid", CallingConvention = CallingConvention.Cdecl)>]
    extern uint getgid()

module Errors =
    // No such file or directory
    [<Literal>]
    let ENOENT = 2
    // Machine is not on the network
    [<Literal>]
    let ENONET = 64

module Stat =
    let S_IFDIR = 0o0040000
    let S_IFREG = 0o0100000

    [<Struct; StructLayout(LayoutKind.Sequential)>]
    type Stat =
        struct
            val mutable st_dev: int64             // Device
            val mutable st_ino: int64             // File serial number
            val mutable st_mode: uint32           // File mode
            val mutable st_nlink: uint32          // Link count
            val mutable st_uid: uint32            // User ID of the file's owner
            val mutable st_gid: uint32            // Group ID of the file's group
            val mutable st_rdev: int64            // Device number, if device
            val mutable __pad1: int64             // Padding
            val mutable st_size: int64            // Size of file, in bytes
            val mutable st_blksize: int32         // Optimal block size for I/O
            val mutable __pad2: int32             // Padding
            val mutable st_blocks: int64          // 512-byte blocks allocated
            val mutable st_atime: int64           // Time of last access
            val mutable st_atimensec: uint64      // Nscecs of last access.
            val mutable st_mtime: int64           // Time of last modification
            val mutable st_mtimensec: uint64      // Nscecs of last modification.
            val mutable st_ctime: int64           // Time of last change
            val mutable st_ctimensec: uint64      // Nscecs of last change.
            val mutable __glibc_reserved_0: int   // Reserved space (2 integers - int[2]
            val mutable __glibc_reserved_1: int   // Reserved space (2 integers - int[2]
        end
