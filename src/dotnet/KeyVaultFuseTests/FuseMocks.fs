module FuseMocks

open System
open System.Runtime.InteropServices
open FSharp.NativeInterop
open KeyVaultFuse
open Libc
open Stat
open Fuse
open Operations

module Mocks =

    let getAttributes : GetAttributes =
        fun path ->
            let statBasicInfo() =
                let mutable stat = Stat()
                stat.st_uid <- getuid()
                stat.st_gid <- getgid()
                let now = DateTimeOffset.Now.ToUnixTimeSeconds()
                stat.st_atime <- now
                stat.st_atimensec <- uint64(now) * 1000000000UL
                stat.st_ctime <- now
                stat.st_ctimensec <- uint64(now) * 1000000000UL
                stat.st_mtime <- now
                stat.st_mtimensec <- uint64(now) * 1000000000UL
                stat
            match path with
            | "/"
            | "/secrets"
            | "/certificates" ->
                let mutable stat = statBasicInfo()
                stat.st_mode <- uint32 (S_IFDIR ||| 0o0755)
                stat.st_nlink <- 2u
                stat.st_size <- 4096L // Linux directory metadata min size
                stat |> Some
            | "/certificates/bigcert" ->
                let mutable stat = statBasicInfo()
                stat.st_mode <- uint32 (S_IFREG ||| 0o0444)
                stat.st_nlink <- 1u
                stat.st_size <- int64 FakeContent.HugeFile.contentLength
                stat |> Some
            | "/whatevs" ->
                let mutable stat = statBasicInfo()
                stat.st_mode <- uint32 (S_IFREG ||| 0o0444)
                stat.st_nlink <- 1u
                stat.st_size <- int64 FakeContent.SmallFile.contentLength
                stat |> Some
            |_ ->
                None
    let readDir : ReadDirectory =
        fun path ->
            [
                "."
                ".."
                if path = "/" then
                    "secrets"
                    "certificates"
                    "whatevs"
                if path = "/certificates" then
                    "bigcert"
            ]
    let readFile : ReadFile =
        fun path ->
            match path with
            | "/certificates/bigcert" ->
                FakeContent.HugeFile.contentBytes
            | "/whatevs" ->
                FakeContent.SmallFile.contentBytes
            | _ ->
                [||]

    let fuseOps = 
        fuse_operations(
            getattr = Marshal.GetFunctionPointerForDelegate<_>(
                GetAttrDelegate(fun (path:string) statPtr fileInfoPtr ->
                    System.Diagnostics.Debug.WriteLine("Getting attributes... at '{0}'", path)
                    NativePtr.clear statPtr
                    match getAttributes path with
                    | Some stat ->
                        stat |> NativePtr.write statPtr
                        0
                    | None ->
                        -Errors.ENOENT
                )
            ),
            (*opendir = Marshal.GetFunctionPointerForDelegate<_>(
                OpenDirDelegate(fun path fileInfoPtr ->
                    System.Diagnostics.Debug.WriteLine("Opening directory... at '{0}'", path)
                    0
                )
            ),*)
            readdir = Marshal.GetFunctionPointerForDelegate<_>(
                ReadDirDelegate(fun path buffer fillerPtr offset fileInfo flags -> 
                    System.Diagnostics.Debug.WriteLine("Reading directory '{0}'", path)
                    let filler = Marshal.GetDelegateForFunctionPointer<FuseFillDirDelegate>(fillerPtr)
                    let FUSE_FILL_DIR_DEFAULTS = 0
                    readDir path
                    |> List.iter(fun file -> filler.Invoke(buffer, file, NativePtr.nullPtr<Stat>, 0L, FUSE_FILL_DIR_DEFAULTS) |> ignore)
                    0
                )
            ),
            init = Marshal.GetFunctionPointerForDelegate<_>(
                InitDelegate(fun connPtr configPtr -> 
                    System.Diagnostics.Debug.WriteLine("Init...")
                    // Implementation of native call here
                    let fuseConnInfo = NativePtr.read connPtr
                    System.Diagnostics.Debug.WriteLine("Proto Major: {0}", fuseConnInfo.proto_major)
                    System.Diagnostics.Debug.WriteLine("Proto Minor: {0}", fuseConnInfo.proto_minor)
                    let mutable fuseConfig = NativePtr.read configPtr
                    fuseConfig.kernel_cache <- 1
                    fuseConfig |> NativePtr.write configPtr
                    System.Diagnostics.Debug.WriteLine("Kernel Cache: {0}", fuseConfig.kernel_cache)
                )
            ),
            read = Marshal.GetFunctionPointerForDelegate<_>(
                ReadDelegate(fun path buffPtr size offset fi -> 
                    System.Diagnostics.Debug.WriteLine("Reading from '{0}' size {1} offset {2}", path, size, offset)
                    let contentBytes = readFile path
                    let contentLength = contentBytes.LongLength
                    let mutable size = size
                    if contentLength > 0L then
                        let mutable length = 0L
                        length <- contentLength
                        if(offset < length) then
                            System.Diagnostics.Debug.WriteLine("offset ({0}) < length {1}", offset, length)
                            if(uint64 offset + size > uint64 length) then
                                size <- uint64 <| length - offset
                            Marshal.Copy(contentBytes, int(offset), buffPtr, int(size))
                        else // offset is beyond the length of the file
                            System.Diagnostics.Debug.WriteLine("offset ({0}) >= length {1}", offset, length)
                            size <- 0UL
                    else
                        size <- 0UL
                    int(size)
                )
            )
        )
    fuseOps

/// Can be used to initialize a FUSE filesystem with mock operations.
let init _ =
    let fuseOpPtr = NativePtr.stackalloc<fuse_operations>1
    let fuseOpSize = Marshal.SizeOf<fuse_operations>() |> uint32
    NativePtr.initBlock fuseOpPtr 0uy fuseOpSize
    Mocks.fuseOps |> NativePtr.write fuseOpPtr
    let args = [| "KeyVaultFuseIntegration"; "-o"; "allow_other"; "-d"; "-f"; "/kvfs" |]
    let ret = fuse_main_real(args.Length, args, fuseOpPtr |> NativePtr.toNativeInt, fuseOpSize |> int64, IntPtr.Zero)                
    ret
