namespace KeyVaultFuse

open System
open System.Runtime.InteropServices
open Microsoft.FSharp.NativeInterop
open Libc
open Stat
open Fuse
open Operations
open Azure.Security.KeyVault.Secrets


module Program =

    /// Usage KeyVaultFuse <vaultUrl> <mount>
    [<EntryPoint>]
    let main args =

        if args.Length = 0 then
            System.Console.Error.WriteLine("Usage: KeyVaultFuse <vaultUrl> <mount>")
            -1
        else

            let printStrArr (arr:string array) =
                arr |> Array.iter (fun s -> System.Console.WriteLine("\t{0}", s))

            System.Console.WriteLine("Configuring FUSE...")
            let fuseOpPtr = NativePtr.stackalloc<fuse_operations>1
            let ret =
                if NativePtr.isNullPtr fuseOpPtr then
                    System.Console.Error.WriteLine("Failed to allocate memory for FUSE operations.")
                    -1
                else
                    let fuseOpSize = Marshal.SizeOf<fuse_operations>() |> uint32
                    NativePtr.initBlock fuseOpPtr 0uy fuseOpSize
                    // allow_other option enables non-root access to the filesystem
                    //let args = [| "KeyVaultFuse"; "-o"; "allow_other"; "-d"; "-f"; "/kvfs" |]
                    System.Console.WriteLine("Starting FUSE... with args:")
                    args |> printStrArr
                    let vaultUri =
                        match Uri.TryCreate(args[0], UriKind.Absolute) with
                        | true, vaultUri -> vaultUri
                        | false, _ ->
                            let uriBuilder = UriBuilder(Scheme="https")
                            if args[0].Contains '.' then
                                uriBuilder.Host <- args[0]
                            else
                                uriBuilder.Host <- args[0] + ".vault.azure.net"
                            uriBuilder.Uri
                    use kvCache = new CachePolicy.KeyVaultCache()
                    let secretClientOptions = SecretClientOptions();
                    // Unless cache is disabled, add the cache policy to the secret client options.
                    if not (args |> Array.contains "disable_cache") then
                        secretClientOptions.AddPolicy(kvCache, Azure.Core.HttpPipelinePosition.PerCall)
                    KeyVaultSecretFuse.SecretClient <-
                        SecretClient(vaultUri, Azure.Identity.DefaultAzureCredential(), secretClientOptions)
                    KeyVaultSecretFuse.FuseOps |> NativePtr.write fuseOpPtr
                    let fuseRet = fuse_main_real(args.Length, args, fuseOpPtr |> NativePtr.toNativeInt, fuseOpSize |> int64, IntPtr.Zero)                
                    fuseRet
            System.Console.WriteLine("FUSE exited.")
            ret
