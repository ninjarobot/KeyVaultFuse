(*
MIT License

Copyright (c) 2025 Dave Curylo

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit
persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*)
namespace KeyVaultFuse

open System
open System.Runtime.InteropServices
open Azure.Security.KeyVault.Certificates
open Azure.Security.KeyVault.Keys
open Azure.Security.KeyVault.Secrets
open Microsoft.FSharp.NativeInterop
open Fuse
open Microsoft.Extensions.DependencyInjection
open Microsoft.Extensions.Logging


module Program =

    type FuseHost (logger:ILogger<FuseHost>, kvCache:CachePolicy.KeyVaultCache) =
        member this.startFuse (args:string array) =
            logger.LogInformation "Configuring FUSE..."
            let fuseOpPtr = NativePtr.stackalloc<fuse_operations>1
            if NativePtr.isNullPtr fuseOpPtr then
                logger.LogError "Failed to allocate memory for FUSE operations."
                -1
            else
                let fuseOpSize = Marshal.SizeOf<fuse_operations>() |> uint32
                NativePtr.initBlock fuseOpPtr 0uy fuseOpSize
                // allow_other option enables non-root access to the filesystem
                //let args = [| "some-key-vault"; "-o"; "allow_other"; "-d"; "-f"; "/kvfs" |]
                let logStartArgs =
                    let sb = System.Text.StringBuilder()
                    sb.AppendLine "Starting FUSE... with args:"
                    for s in args do
                        sb.AppendFormat (String.Format("\t{0}", s))
                    sb.ToString()
                logger.LogInformation logStartArgs
                logger.LogInformation("Mounting to: {0}", args[1])
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
                logger.LogInformation("Vault URI: {0}", vaultUri)
                let credential = Azure.Identity.DefaultAzureCredential(includeInteractiveCredentials = false)
                let certificateClientOptions = CertificateClientOptions()
                certificateClientOptions.AddPolicy(kvCache, Azure.Core.HttpPipelinePosition.PerCall)
                KeyVaultSecretFuse.CertificateClient <-
                    CertificateClient(vaultUri, credential, certificateClientOptions)
                let keyClientOptions = KeyClientOptions()
                keyClientOptions.AddPolicy(kvCache, Azure.Core.HttpPipelinePosition.PerCall)
                KeyVaultSecretFuse.KeyClient <-
                    KeyClient(vaultUri, credential, keyClientOptions)
                let secretClientOptions = SecretClientOptions();
                // Unless cache is disabled, add the cache policy to the secret client options.
                if not (args |> Array.contains "disable_cache") then
                    secretClientOptions.AddPolicy(kvCache, Azure.Core.HttpPipelinePosition.PerCall)
                KeyVaultSecretFuse.SecretClient <-
                    SecretClient(vaultUri, credential, secretClientOptions)
                KeyVaultSecretFuse.FuseOps |> NativePtr.write fuseOpPtr
                let fuseOptions = $"{args[0]} -o allow_other -f {args[1]}".Split null
                fuse_main_real(fuseOptions.Length, fuseOptions, fuseOpPtr |> NativePtr.toNativeInt, fuseOpSize |> int64, IntPtr.Zero)                

    /// Usage KeyVaultFuse <vaultUrl> <mount>
    [<EntryPoint>]
    let main args =

        if args.Length = 0 then
            Console.Error.WriteLine "Usage: KeyVaultFuse <vaultUrl> <mount>"
            -1
        else
            let ret =
                ServiceCollection()
                    .AddSingleton<FuseHost>()
                    .AddSingleton<CachePolicy.KeyVaultCache>()
                    .AddLogging(fun builder -> builder.AddSimpleConsole() |> ignore)
                    .BuildServiceProvider()
                    .GetService<FuseHost>()
                    .startFuse args
            Console.Out.WriteLine "FUSE exited."
            ret
