module FuseDelegates

open System
open System.Runtime.InteropServices
open FSharp.NativeInterop
open KeyVaultFuse.Operations
open KeyVaultFuse.Fuse
open KeyVaultFuse.Libc
open KeyVaultFuse.Stat
open Expecto

module Mocks =

    module SmallFile =
        let contents =
            "Hello, world!"
        let contentBytes = System.Text.Encoding.UTF8.GetBytes(contents)
        let contentLength = contentBytes.LongLength

    module HugeFile =
        let contents =
            Security.Cryptography.RandomNumberGenerator.GetBytes(1024 * 10) |> Convert.ToBase64String
        let contentBytes = System.Text.Encoding.UTF8.GetBytes(contents)
        let contentLength = contentBytes.LongLength

    let getAttributesMock : GetAttributes =
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
                stat.st_size <- int64 HugeFile.contentLength
                stat |> Some
            | "/whatevs" ->
                let mutable stat = statBasicInfo()
                stat.st_mode <- uint32 (S_IFREG ||| 0o0444)
                stat.st_nlink <- 1u
                stat.st_size <- int64 SmallFile.contentLength
                stat |> Some
            |_ ->
                None
    let readDirMock : ReadDirectory =
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
    let readFileMock : ReadFile =
        fun path ->
            match path with
            | "/certificates/bigcert" ->
                HugeFile.contentBytes
            | "/whatevs" ->
                SmallFile.contentBytes
            | _ ->
                [||]



[<Tests>]
let tests =
    testList
        "FuseDelegates"
        [ 
            test "getRootDirAttributes" {
                let fuseOperations = KeyVaultFuse.Mocks.fuseOps
                let getAttr: GetAttrDelegate =
                    Marshal.GetDelegateForFunctionPointer fuseOperations.getattr
                let statPtr: nativeptr<Stat> = NativePtr.stackalloc 1
                let fuseFileInfoPtr: nativeptr<fuse_file_info> = NativePtr.stackalloc 1
                let res = getAttr.Invoke("/", statPtr, fuseFileInfoPtr)
                Expect.equal res 0 "Expected 0 return value"
                let stat = NativePtr.read statPtr
                Expect.equal stat.st_nlink 2u "Expected 2u for a directory"
                Expect.equal (int32 stat.st_mode &&& S_IFDIR) S_IFDIR "Expected mode = directory 0040000"
                Expect.equal (int32 stat.st_mode &&& 0o0755) 0o0755 "Expected executable dir 0755"
            }
            test "getSubDirAttributes" {
                let fuseOperations = KeyVaultFuse.Mocks.fuseOps
                let getAttr: GetAttrDelegate =
                    Marshal.GetDelegateForFunctionPointer fuseOperations.getattr
                let statPtr: nativeptr<Stat> = NativePtr.stackalloc 1
                let fuseFileInfoPtr: nativeptr<fuse_file_info> = NativePtr.stackalloc 1
                let res = getAttr.Invoke("/certificates", statPtr, fuseFileInfoPtr)
                Expect.equal res 0 "Expected 0 return value"
                let stat = NativePtr.read statPtr
                Expect.equal stat.st_nlink 2u "Expected 2u for a directory"
                Expect.equal (int32 stat.st_mode &&& S_IFDIR) S_IFDIR "Expected mode = directory 0040000"
                Expect.equal (int32 stat.st_mode &&& 0o0755) 0o0755 "Expected executable dir 0755"
            }
            test "getFileAttributes" {
                let fuseOperations = KeyVaultFuse.Mocks.fuseOps
                let getAttr: GetAttrDelegate =
                    Marshal.GetDelegateForFunctionPointer fuseOperations.getattr
                let statPtr: nativeptr<Stat> = NativePtr.stackalloc 1
                let fuseFileInfoPtr: nativeptr<fuse_file_info> = NativePtr.stackalloc 1
                let res = getAttr.Invoke("/whatevs", statPtr, fuseFileInfoPtr)
                Expect.equal res 0 "Expected 0 return value"
                let stat = NativePtr.read statPtr
                Expect.equal stat.st_nlink 1u "Expected 1u for a file"
                Expect.equal stat.st_size 13L "Expected 13 bytes for file size"
                Expect.equal (int32 stat.st_mode &&& S_IFREG) S_IFREG "Expected mode = regular file 0100000"
                Expect.equal (int32 stat.st_mode &&& 0o0444) 0o0444 "Expected read only file 0444"
            }
            test "readRootDir" {
                let fuseOperations = KeyVaultFuse.Mocks.fuseOps
                let readDir: ReadDirDelegate =
                    Marshal.GetDelegateForFunctionPointer fuseOperations.readdir
                let nodeNames = ResizeArray()
                let filler: FuseFillDirDelegate = FuseFillDirDelegate(fun _ name _ _ _ -> nodeNames.Add name; 0)
                let fillerPtr = Marshal.GetFunctionPointerForDelegate filler
                let fuseFileInfoPtr: nativeptr<fuse_file_info> = NativePtr.stackalloc 1
                let res = readDir.Invoke("/", System.IntPtr.Zero, fillerPtr, 0L, fuseFileInfoPtr, 0)
                Expect.equal res 0 "Expected 0 return value"
                Expect.containsAll nodeNames [ "."; ".."; "secrets"; "certificates"; "whatevs" ] "Expected all nodes to be present"
            }
            test "readSubDir" {
                let fuseOperations = KeyVaultFuse.Mocks.fuseOps
                let readDir: ReadDirDelegate =
                    Marshal.GetDelegateForFunctionPointer fuseOperations.readdir
                let nodeNames = ResizeArray()
                let filler: FuseFillDirDelegate = FuseFillDirDelegate(fun _ name _ _ _ -> nodeNames.Add name; 0)
                let fillerPtr = Marshal.GetFunctionPointerForDelegate filler
                let fuseFileInfoPtr: nativeptr<fuse_file_info> = NativePtr.stackalloc 1
                let res = readDir.Invoke("/certificates", System.IntPtr.Zero, fillerPtr, 0L, fuseFileInfoPtr, 0)
                Expect.equal res 0 "Expected 0 return value"
                Expect.containsAll nodeNames [ "."; ".."; "bigcert" ] "Expected all nodes to be present"
            }
            test "readSmallFile" {
                let fuseOperations = KeyVaultFuse.Mocks.fuseOps
                let read: ReadDelegate =
                    Marshal.GetDelegateForFunctionPointer fuseOperations.read
                let buffer : nativeptr<byte> = NativePtr.stackalloc 1024
                let fuseFileInfoPtr: nativeptr<fuse_file_info> = NativePtr.stackalloc 1
                let sizeRead = read.Invoke("/whatevs", buffer |> NativePtr.toNativeInt, 1024UL, 0L, fuseFileInfoPtr)
                Expect.equal sizeRead 13 "Expected 13 bytes to be read"
                let content : byte array = Array.zeroCreate 13
                Marshal.Copy(buffer |> NativePtr.toNativeInt, content, 0, sizeRead)
                let contentStr = System.Text.Encoding.UTF8.GetString(content)
                Expect.equal contentStr "Hello, world!" "Expected file content to be 'Hello, world!'"
            }
            test "readLargeFile" {
                let fuseOperations = KeyVaultFuse.Mocks.fuseOps
                let read: ReadDelegate =
                    Marshal.GetDelegateForFunctionPointer fuseOperations.read
                let buffer : nativeptr<byte> = NativePtr.stackalloc 1024
                let fuseFileInfoPtr: nativeptr<fuse_file_info> = NativePtr.stackalloc 1
                let allContent = ResizeArray()
                let mutable sizeRead = 1024 // just something more than 0
                while sizeRead > 0 do
                    sizeRead <- read.Invoke("/certificates/bigcert", buffer |> NativePtr.toNativeInt, 1024UL, allContent.Count, fuseFileInfoPtr)
                    let content : byte array = Array.zeroCreate sizeRead
                    Marshal.Copy(buffer |> NativePtr.toNativeInt, content, 0, sizeRead)
                    allContent.AddRange content
                let contentStr = System.Text.Encoding.UTF8.GetString(allContent.ToArray())
                let contentBytes = System.Convert.FromBase64String contentStr
                Expect.hasLength contentBytes 10240 "Expected 10240 bytes to be read"
            }
        ]
