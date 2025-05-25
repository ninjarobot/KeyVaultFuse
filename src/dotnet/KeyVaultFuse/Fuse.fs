namespace KeyVaultFuse

open System
open System.Runtime.InteropServices
open Stat

module Fuse =

    [<Struct; StructLayout(LayoutKind.Sequential)>]
    type fuse_opt =
        struct
            val mutable templ:string
            val mutable offset:uint64
            val mutable value:int
        end

    [<Struct>]
    [<System.Runtime.CompilerServices.InlineArray(22)>]
    type fuse_conn_info_reserved =
        struct
            val reserved0:int
        end

    [<Struct; StructLayout(LayoutKind.Sequential)>]
    type fuse_conn_info =
        struct
            val proto_major:uint
            val proto_minor:uint
            val mutable max_write:uint
            val mutable max_read:uint
            val mutable max_readahead:uint
            val capable:uint
            val mutable want:uint
            val mutable max_background:uint
            val mutable congestion_threshold:uint
            val mutable time_gran:uint
            val reserved:fuse_conn_info_reserved
        end

    [<Struct; StructLayout(LayoutKind.Sequential)>]
    type fuse_file_info =
        struct
            val mutable flags:int
            val mutable writepage:int
            val mutable direct_io:uint
            val mutable keep_cache:uint
            val mutable flush:uint
            val mutable nonseekable:uint
            val mutable flock_release:uint
            val mutable cache_readdir:uint        
            val padding0:uint
            val padding1:uint
            val mutable fh:uint64
            val mutable lock_owner:uint64
            val mutable poll_events:uint
        end

    [<Struct; StructLayout(LayoutKind.Sequential)>]
    type fuse_config =
        struct
            val mutable set_gid:int
            val mutable gid:uint
            val mutable set_uid:int
            val mutable uid:uint
            val mutable set_mode:int
            val mutable umask:uint
            val mutable entry_timeout:double
            val mutable negative_timeout:double
            val mutable attr_timeout:double
            val mutable intr:int
            val mutable intr_signal:int
            val mutable remember:int
            val mutable hard_remove:int
            val mutable use_ino:int
            val mutable readdir_ino:int
            val mutable direct_io:int
            val mutable kernel_cache:int
            val mutable auto_cache:int
            val mutable ac_attr_timeout_set:int
            val mutable ac_attr_timeout:double
            val mutable nullpath_ok:int
            (*
             * The remaining options are used by libfuse internally and
             * should not be touched.
             *)
            val show_help:int
            val modules:nativeint
            val debug:int
        end

    // (const char *, struct stat *, struct fuse_file_info *fi)
    [<UnmanagedFunctionPointer(CallingConvention.Cdecl)>]
    type GetAttrDelegate = delegate of path:string * nativeptr<Stat> * nativeptr<fuse_file_info> -> int

    // (const char *, void *, fuse_fill_dir_t, off_t, struct fuse_file_info *, enum fuse_readdir_flags)
    [<UnmanagedFunctionPointer(CallingConvention.Cdecl)>]
    type ReadDirDelegate = delegate of path:string * buffer:nativeint * filler:nativeint * offset:int64 * nativeptr<fuse_file_info> * int -> int

    // (const char *, struct fuse_file_info *)
    [<UnmanagedFunctionPointer(CallingConvention.Cdecl)>]
    type OpenDirDelegate = delegate of path:string * nativeptr<fuse_file_info> -> int

    //void *(*init) (struct fuse_conn_info *conn);
    [<UnmanagedFunctionPointer(CallingConvention.Cdecl)>]
    type InitDelegate = delegate of nativeptr<fuse_conn_info> * nativeptr<fuse_config> -> unit

    [<UnmanagedFunctionPointer(CallingConvention.Cdecl)>]
    type OpenDelegate = delegate of path:string * nativeptr<fuse_file_info> -> int

    //int (*write) (const char *, const char *, size_t, off_t, struct fuse_file_info *)
    [<UnmanagedFunctionPointer(CallingConvention.Cdecl)>]
    type WriteDelegate = delegate of path:string * nativeptr<char> * int * int * nativeptr<fuse_file_info> -> int

    [<UnmanagedFunctionPointer(CallingConvention.Cdecl)>]
    type ReadDelegate = delegate of path:string * buffPtr:nativeint * size:uint64 * offset:int64 * fi:nativeptr<fuse_file_info> -> int

    [<UnmanagedFunctionPointer(CallingConvention.Cdecl)>]
    type FuseFillDirDelegate = delegate of buf:nativeint * string * nativeptr<Stat> * off:int64 * fuse_fill_dir_flags:int -> int

    [<Struct; StructLayout(LayoutKind.Sequential)>]
    type fuse_operations =
        struct
            val mutable getattr: nativeint
            val mutable readlink: nativeint
            val mutable mknod: nativeint
            val mutable mkdir: nativeint
            val mutable unlink: nativeint
            val mutable rmdir: nativeint
            val mutable symlink: nativeint
            val mutable rename: nativeint
            val mutable link: nativeint
            val mutable chmod: nativeint
            val mutable chown: nativeint
            val mutable truncate: nativeint
            val mutable open': nativeint
            val mutable read: nativeint
            val mutable write: nativeint
            val mutable statfs: nativeint
            val mutable flush: nativeint
            val mutable release: nativeint
            val mutable fsync: nativeint
            val mutable setxattr: nativeint
            val mutable getxattr: nativeint
            val mutable listxattr: nativeint
            val mutable removexattr: nativeint
            val mutable opendir: nativeint
            val mutable readdir: nativeint
            val mutable releasedir: nativeint
            val mutable fsyncdir: nativeint
            val mutable init: nativeint
            val mutable destroy: nativeint
            val mutable access: nativeint
            val mutable create: nativeint
            val mutable lock: nativeint
            val mutable utimens: nativeint
            val mutable bmap: nativeint
            val mutable ioctl: nativeint
            val mutable poll: nativeint
            val mutable write_buf: nativeint
            val mutable read_buf: nativeint
            val mutable flock: nativeint
            val mutable fallocate: nativeint
            val mutable copy_file_range: nativeint
            val mutable lseek: nativeint
        end

    [<DllImport("libfuse3.so.3", CallingConvention = CallingConvention.Cdecl)>]
    extern int fuse_main_real(int argc, string[] argv, IntPtr op, int64 size, IntPtr private_data)

    type fuse_log_level =
        | FUSE_LOG_EMERG = 0
        | FUSE_LOG_ALERT = 1
        | FUSE_LOG_CRIT = 2
        | FUSE_LOG_ERR = 3
        | FUSE_LOG_WARNING = 4
        | FUSE_LOG_NOTICE = 5
        | FUSE_LOG_INFO = 6
        | FUSE_LOG_DEBUG = 7

    //[<DllImport("libfuse3.so.3", CallingConvention = CallingConvention.Cdecl)>]
    //extern void fuse_log(fuse_log_level level, string fmt);
    let fuse_log(level, fmt:string) =
        System.Console.WriteLine(fmt)