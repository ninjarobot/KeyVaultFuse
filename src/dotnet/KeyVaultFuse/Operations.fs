namespace KeyVaultFuse

open Stat

module Operations =

    /// Accepts a path and returns a Stat if there is a file or directory at that path.
    type GetAttributes = string -> Stat option

    /// Returns a list of names of subdirectories and files in a directory.
    type ReadDirectory = string -> string list

    /// Reads the contents of a file into a byte array. Strings should be UTF-8.
    type ReadFile = string -> byte[]
