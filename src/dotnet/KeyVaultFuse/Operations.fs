namespace KeyVaultFuse

open System
open System.Runtime.InteropServices
open Microsoft.FSharp.NativeInterop
open Libc
open Stat
open Fuse

module FakeContent =
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


module Operations =

    /// Accepts a path and returns a Stat if there is a file or directory at that path.
    type GetAttributes = string -> Stat option

    /// Returns a list of names of subdirectories and files in a directory.
    type ReadDirectory = string -> string list

    /// Reads the contents of a file into a byte array. Strings should be UTF-8.
    type ReadFile = string -> byte[]
