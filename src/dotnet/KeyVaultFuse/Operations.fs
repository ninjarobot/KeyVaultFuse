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

open Stat

module Operations =

    /// Accepts a path and returns a Stat if there is a file or directory at that path.
    type GetAttributes = string -> Stat option

    /// Returns a list of names of subdirectories and files in a directory.
    type ReadDirectory = string -> string list

    /// Reads the contents of a file into a byte array. Strings should be UTF-8.
    type ReadFile = string -> byte[]
    
    /// Opens a file - not supported, but implemented to provide a log message.
    type OpenFile = string -> int

    /// Writes a file - not supported, but implemented to provide a meaningful error response.
    type Write = string -> int
