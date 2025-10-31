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
module KeyVaultBehaviors

open System
open Expecto
open Microsoft.Extensions.DependencyInjection
open Microsoft.Extensions.Logging
open Moq
open Azure
open Azure.Identity
open Azure.Security.KeyVault.Certificates
open Azure.Security.KeyVault.Keys
open Azure.Security.KeyVault.Secrets
open KeyVaultFuse

module MockSecrets =
    module Secret1Versions =
        let v1 =
            SecretModelFactory.KeyVaultSecret(
                SecretModelFactory.SecretProperties(
                    name = "testSecret1",
                    createdOn = DateTimeOffset.Now - TimeSpan.FromDays 3.,
                    updatedOn = DateTimeOffset.Now - TimeSpan.FromDays 2.,
                    version = "v001"
                )
            , "foo")
        let v2 =
            let props = SecretModelFactory.SecretProperties(
                    name = "testSecret1",
                    createdOn = DateTimeOffset.Now - TimeSpan.FromDays 2.,
                    updatedOn = DateTimeOffset.Now - TimeSpan.FromDays 1.,
                    version = "v002"
                )
            props.ExpiresOn <- DateTimeOffset.Now - TimeSpan.FromHours 2.
            props
            SecretModelFactory.KeyVaultSecret(props, "bar")
        let v3 =
            SecretModelFactory.KeyVaultSecret(
                SecretModelFactory.SecretProperties(
                    name = "testSecret1",
                    createdOn = DateTimeOffset.Now - TimeSpan.FromDays 1.,
                    updatedOn = DateTimeOffset.Now - TimeSpan.FromHours 4.,
                    version = "v003"
                )
            , "baz")
        let allProperties = [v1.Properties; v2.Properties; v3.Properties]
    module Secret2Versions =
        let v1 =
            SecretModelFactory.KeyVaultSecret(
                SecretModelFactory.SecretProperties(
                    name = "testSecret2",
                    createdOn = DateTimeOffset.Now - TimeSpan.FromDays 12.,
                    updatedOn = DateTimeOffset.Now - TimeSpan.FromDays 12.,
                    version = "v101"
                )
            , "yeet")
        let v2 =
            let props = SecretModelFactory.SecretProperties(
                    name = "testSecret2",
                    createdOn = DateTimeOffset.Now - TimeSpan.FromDays 4.,
                    updatedOn = DateTimeOffset.Now - TimeSpan.FromDays 1.,
                    version = "v102"
                )
            props.ExpiresOn <- DateTimeOffset.Now - TimeSpan.FromHours 8.
            props
            SecretModelFactory.KeyVaultSecret(props, "deet")
        let allProperties = [v1.Properties; v2.Properties]

type MockCertificateClient() =
    inherit CertificateClient()

type MockKeyClient() =
    inherit KeyClient()

type MockSecretClient() =
    inherit SecretClient()
    override _.GetSecret(secretName: string, version: string, _:Threading.CancellationToken) =
        let secret =
            match version with
            | null -> MockSecrets.Secret1Versions.v3
            | "v001" -> MockSecrets.Secret1Versions.v1
            | "v002" -> MockSecrets.Secret1Versions.v2
            | "v003" -> MockSecrets.Secret1Versions.v3
            | _ -> null
        Response.FromValue(secret, Mock.Of<Response>())
    /// Should return the properties of the most recent version of the mock secrets.
    override _.GetPropertiesOfSecrets (cancellationToken: Threading.CancellationToken): Pageable<SecretProperties> = 
        Pageable.FromPages([Page.FromValues([MockSecrets.Secret1Versions.v3.Properties; MockSecrets.Secret2Versions.v2.Properties], null, Mock.Of<Response>())])
    /// Should return the properties of the versions of the the mock secret passed.
    override _.GetPropertiesOfSecretVersions (name:string, cancellationToken: Threading.CancellationToken): Pageable<SecretProperties> = 
        match name with 
        | "testSecret1" ->
            Pageable.FromPages([Page.FromValues(MockSecrets.Secret1Versions.allProperties, null, Mock.Of<Response>())])
        | "testSecret2" ->
            Pageable.FromPages([Page.FromValues(MockSecrets.Secret2Versions.allProperties, null, Mock.Of<Response>())])
        | _ -> 
            Pageable.FromPages([Page.FromValues([], null, Mock.Of<Response>())])

let mocks() =
    MockCertificateClient(), MockKeyClient(), MockSecretClient()

[<Tests>]
let verifyingMocks = testList "Verifying SecretClientMock" [
    test "GetSecret Default Version" {
        let s = MockSecretClient().GetSecret("testSecret1")
        Expect.equal s.Value.Name "testSecret1" "Name incorrect"
        Expect.equal s.Value.Value "baz" "Value incorrect"
        Expect.equal s.Value.Properties.Version "v003" "Version incorrect"
    }
    test "GetSecret Specific Version" {
        let s = MockSecretClient().GetSecret("testSecret1", "v001")
        Expect.equal s.Value.Name "testSecret1" "Name incorrect"
        Expect.equal s.Value.Value "foo" "Value incorrect"
        Expect.equal s.Value.Properties.Version "v001" "Version incorrect"
    }
]

[<Tests>]
let sortAndFilter = testList "Sort and Filter Secret Versions" [
    test "Get Secret Versions and Order By Date" {
        let pages = MockSecretClient().GetPropertiesOfSecretVersions ("testSecret1")
        let sortedByDate = KeyVaultSecretOperations.sortedByDate pages
        let newest = sortedByDate |> Seq.head
        Expect.equal newest.Version "v003" "Incorrect number of secrets"
    }
    test "Get Secret Verionss and Exclude Expired" {
        let pages = MockSecretClient().GetPropertiesOfSecretVersions ("testSecret1")
        let versions = pages |> KeyVaultSecretOperations.filterExpired |> Seq.map (fun p -> p.Version)
        Expect.hasLength versions 2 "Incorrect number of secret versions"
        Expect.isFalse (versions |> Seq.contains "v002") "v002 should be expired"
    }
    test "Get Secret Versions By Date and Exclude Expired" {
        let pages = MockSecretClient().GetPropertiesOfSecretVersions ("testSecret1")
        let notExpired =
            pages |> (KeyVaultSecretOperations.filterExpired >> KeyVaultSecretOperations.sortedByDate)
        let versions = notExpired |> Seq.map (fun p -> p.Version)
        Expect.sequenceContainsOrder ["v003"; "v001"] versions "Incorrect order of secret versions"
        Expect.hasLength versions 2 "Incorrect number of secret versions"
        Expect.isFalse (versions |> Seq.contains "v002") "v002 should be expired"
    }
]

[<Tests>]
let fuseOperationTests = testList "Fuse operation tests" [
    // Fix these so they test the logic against the mock SecretClient.
    test "Get attributes on secrets" {
        let secretClient = MockSecretClient()
        let secret1Stat = KeyVaultSecretOperations.secretsGetAttributes (mocks()) "/secrets/testSecret1"
        let secret2Stat = KeyVaultSecretOperations.secretsGetAttributes (mocks()) "/secrets/testSecret2"
        let secret1 = Expect.wantSome secret1Stat "testSecret1 stat should not be None"
        Expect.equal secret1.st_size 3L "Incorrect size for testSecret1"
        Expect.isSome secret2Stat "testSecret2 stat should not be None"
    }
    test "List secrets" {
        let secretClient = MockSecretClient()
        let secrets = KeyVaultSecretOperations.keyVaultReadDir (mocks()) "/secrets"
        Expect.containsAll secrets ["."; ".."] "Missing current and parent directories"
        Expect.containsAll secrets ["testSecret1"; "testSecret2"] "Missing secrets"
    }
    test "List secret versions for 'testSecret1'" {
        let secretClient = MockSecretClient()
        let secretVersions = KeyVaultSecretOperations.keyVaultReadDir (mocks()) "/secrets/testSecret1/versions"
        Expect.containsAll secretVersions ["."; ".."] "Missing current and parent directories"
        Expect.containsAll secretVersions ["v001"; "v002"; "v003"] "Missing existing versions"
    }
    test "Read secret version for 'testSecret1'" {
        let secretClient = MockSecretClient()
        let secret =
            KeyVaultSecretOperations.keyVaultReadFile (mocks()) "/secrets/testSecret1/versions/v003"
            |> System.Text.Encoding.UTF8.GetString
        Expect.equal secret MockSecrets.Secret1Versions.v3.Value "Incorrect data for testSecret1 v003"
    }
]

// The native delegates need to be static and depend on a static SecretClient instance.
KeyVaultSecretFuse.SecretClient <- MockSecretClient()

/// These tests share a static instance of the mock SecretClient.
[<Tests>]
let fuseDelegateTests = testList "Fuse delegate tests" [
    test "Get attributes on key vault root" {
        let getAttr = KeyVaultSecretFuse.GetAttrDelegate
        let statPtr = NativeInterop.NativePtr.stackalloc<Stat.Stat>1
        let fileInfoPtr = NativeInterop.NativePtr.stackalloc<Fuse.fuse_file_info>1
        getAttr.Invoke("/", statPtr, fileInfoPtr)
        let stat = NativeInterop.NativePtr.read statPtr
        Expect.equal stat.st_mode (uint32 (Stat.S_IFDIR ||| 0o0755) ) "Incorrect mode for '/'"
        Expect.equal stat.st_size 0L "The '/' directory should have a size of 0"
    }

    test "Get attributes on secret directory" {
        let getAttr = KeyVaultSecretFuse.GetAttrDelegate
        let statPtr = NativeInterop.NativePtr.stackalloc<Stat.Stat>1
        let fileInfoPtr = NativeInterop.NativePtr.stackalloc<Fuse.fuse_file_info>1
        getAttr.Invoke("/secrets", statPtr, fileInfoPtr)
        let stat = NativeInterop.NativePtr.read statPtr
        Expect.equal stat.st_mode (uint32 (Stat.S_IFDIR ||| 0o0755) ) "Incorrect mode for 'secrets'"
        Expect.equal stat.st_size 0L "The 'secrets' directory should have a size of 0"
    }

    test "Get attributes on secret" {
        let getAttr = KeyVaultSecretFuse.GetAttrDelegate
        let statPtr = NativeInterop.NativePtr.stackalloc<Stat.Stat> 1
        let fileInfoPtr = NativeInterop.NativePtr.stackalloc<Fuse.fuse_file_info> 1
        getAttr.Invoke("/secrets/testSecret1", statPtr, fileInfoPtr)
        let stat = NativeInterop.NativePtr.read statPtr
        Expect.equal stat.st_mode (uint32 (Stat.S_IFDIR ||| 0o0755) ) "Incorrect mode for testSecret1"
        Expect.equal stat.st_size 3L "testSecret1 should have the size of the most recent version"
    }

    test "Get attributes on secret value" {
        let getAttr = KeyVaultSecretFuse.GetAttrDelegate
        let statPtr = NativeInterop.NativePtr.stackalloc<Stat.Stat> 1
        let fileInfoPtr = NativeInterop.NativePtr.stackalloc<Fuse.fuse_file_info> 1
        getAttr.Invoke("/secrets/testSecret1/value", statPtr, fileInfoPtr)
        let stat = NativeInterop.NativePtr.read statPtr
        Expect.equal stat.st_mode (uint32 (Stat.S_IFREG ||| 0o0444)) "Incorrect mode for testSecret1 value"
        Expect.equal stat.st_size 3L "Incorrect size for testSecret1 value"
    }

    test "Get attributes on secret versions" {
        let getAttr = KeyVaultSecretFuse.GetAttrDelegate
        let statPtr = NativeInterop.NativePtr.stackalloc<Stat.Stat> 1
        let fileInfoPtr = NativeInterop.NativePtr.stackalloc<Fuse.fuse_file_info> 1
        getAttr.Invoke("/secrets/testSecret1/versions", statPtr, fileInfoPtr)
        let stat = NativeInterop.NativePtr.read statPtr
        Expect.equal stat.st_mode (uint32 (Stat.S_IFDIR ||| 0o0755)) "Incorrect mode for testSecret1 versions"
        Expect.equal stat.st_size 0L "Incorrect size for testSecret1 versions directory"
    }
]

[<Tests>]
let integrationCacheTests = ptestList "Integration Cache Tests" [
    test "Get secret" {
        let serviceProvider =
            ServiceCollection()
                .AddSingleton<CachePolicy.KeyVaultCache>()
                .AddLogging(fun builder -> builder.AddSimpleConsole() |> ignore)
                .BuildServiceProvider()
        let cred = DefaultAzureCredential()
        let secretOptions = SecretClientOptions()
        secretOptions.AddPolicy(serviceProvider.GetRequiredService<CachePolicy.KeyVaultCache>(), Core.HttpPipelinePosition.PerCall)
        let client = new SecretClient(new Uri("https://kvtest467832.vault.azure.net/"), cred, secretOptions)
        let secret = client.GetSecret("cert1")
        Expect.isNotNull secret.Value.Value "Secret value should not be null"
        // Get the secret again, this time it will be in the cache.
        for i in 1..10 do
            let secret = client.GetSecret("cert1")
            Expect.isNotNull secret.Value.Value "Secret value should not be null"
        let props = client.GetPropertiesOfSecrets()
        for p in props do
            System.Console.WriteLine(p.Name)
        ()
        let versions = client.GetPropertiesOfSecretVersions("cert1")
        for i in 1..20 do
            for v in versions do
                System.Console.WriteLine(v.Version)
            ()
    }
]
