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
open Azure.Core
open Azure.Core.Pipeline
open Microsoft.Extensions.Logging
open Microsoft.Extensions.Caching.Memory

module CachePolicy =

    /// Cacheable response. Only difference is that it will copy the content stream to a byte array.
    type ResponseMessageCacheEntry(contentBytes:BinaryData, headers, reasonPhrase, status) =
        inherit Azure.Response()

        let mutable contentBinaryData = contentBytes.ToArray()

        let mutable clientRequestId:string = null

        override this.ClientRequestId
            with get (): string =
                clientRequestId
            and set (v: string): unit =
                clientRequestId <- v
        override this.ContainsHeader(name: string): bool =
            this.Headers.Contains(name)
            
        override this.Content: BinaryData =
            BinaryData(contentBytes)
        override this.ContentStream
            with get (): IO.Stream =
                this.Content.ToStream()
            and set (v: IO.Stream): unit =
                contentBinaryData <- 
                    let binaryData = BinaryData.FromStream(v)
                    binaryData.ToArray()
        override this.Dispose(): unit =
            this.ContentStream.Dispose()
        override this.EnumerateHeaders(): Collections.Generic.IEnumerable<HttpHeader> =
            seq {
                for header in headers do
                    yield header
            }
        override this.Headers: ResponseHeaders =
            headers
        override this.IsError: bool =
            status >= 400
        override this.ReasonPhrase: string =
            reasonPhrase
        override this.Status: int =
            status
        override this.ToString(): string =
            this.ToString()
        override this.TryGetHeader(name: string, value: byref<string>): bool =
            this.Headers.TryGetValue(name, &value)
        override this.TryGetHeaderValues(name: string, values: byref<Collections.Generic.IEnumerable<string>>): bool =
            this.Headers.TryGetValues(name, &values)


    type KeyVaultCache(logger:ILogger<KeyVaultCache>) =
        inherit HttpPipelinePolicy()

        let cache = new MemoryCache(MemoryCacheOptions())

        let processNext = HttpPipelinePolicy.ProcessNext
        let processNextAsync = HttpPipelinePolicy.ProcessNextAsync

        interface IDisposable with
            member this.Dispose() =
                cache.Dispose()
                GC.SuppressFinalize(this);

        override _.Process(message: HttpMessage, pipeline: ReadOnlyMemory<HttpPipelinePolicy>): unit =
            if message.Request.Method = RequestMethod.Get then
                let uriPath = message.Request.Uri.Path
                System.Console.WriteLine("Processing request for {0}", uriPath)
                if uriPath.StartsWith("/secrets/", StringComparison.OrdinalIgnoreCase)
                   || uriPath.StartsWith("/certificates/", StringComparison.OrdinalIgnoreCase)
                   || uriPath.StartsWith("/keys/", StringComparison.OrdinalIgnoreCase) then
                    message.Response <- cache.GetOrCreate(uriPath, fun cacheEntry ->
                        System.Console.WriteLine("Cache miss for {0}", uriPath)
                        processNext(message, pipeline)
                        if message.Response.IsError then
                            let expiry =
                                match message.Response.Status with
                                | 401 -> TimeSpan.FromSeconds(0.1) // Expire quickly so it can retry with a new auth token.
                                | _ -> TimeSpan.FromSeconds(5.)
                            cacheEntry.AbsoluteExpirationRelativeToNow <- expiry
                            logger.LogInformation("Added to cache for {0} with {1} seconds expiry", uriPath, expiry.TotalSeconds)
                        else // Default expiry for successful responses
                            cacheEntry.AbsoluteExpirationRelativeToNow <- TimeSpan.FromMinutes(5.)
                            logger.LogInformation("Added to cache for {0} with 5 minutes expiry", uriPath)
                        new ResponseMessageCacheEntry(message.Response.Content, message.Response.Headers, message.Response.ReasonPhrase, message.Response.Status)
                    )
                else
                    HttpPipelinePolicy.ProcessNext(message, pipeline)
            else
                HttpPipelinePolicy.ProcessNext(message, pipeline)

        override this.ProcessAsync(message: HttpMessage, pipeline: ReadOnlyMemory<HttpPipelinePolicy>): Threading.Tasks.ValueTask =
            failwith "Not Implemented"
