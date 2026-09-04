using System.Diagnostics;
using System.Globalization;
using System.Net;

// Measures the token endpoint under a fixed number of concurrent callers.
//
//   dotnet run --project load/Keyward.LoadTests -- http://localhost:5100 2000 32
//
// The client credentials grant is the one measured, and that is deliberate. It is the grant that runs in
// a loop in production: a service asks for a token every few minutes, forever, while an interactive
// sign-in happens once a day and spends most of its wall clock waiting for somebody to type a password.
// Averaging the two would produce a number that describes neither.
//
// There is a k6 script alongside this for anyone who wants arrival-rate scheduling and a nicer report.
// This exists because it needs nothing installed, which means the numbers in the README can be reproduced
// with the repository and a container runtime.

string host = args.Length > 0 ? args[0].TrimEnd('/') : "http://localhost:5100";
int requests = args.Length > 1 ? int.Parse(args[1], CultureInfo.InvariantCulture) : 2000;
int concurrency = args.Length > 2 ? int.Parse(args[2], CultureInfo.InvariantCulture) : 32;

var handler = new SocketsHttpHandler
{
    // Enough connections that the client is not the bottleneck. Measuring your own connection pool is a
    // classic way to publish a number about the wrong program.
    MaxConnectionsPerServer = concurrency * 2,
    PooledConnectionLifetime = TimeSpan.FromMinutes(5),
};

using var client = new HttpClient(handler) { BaseAddress = new Uri(host) };

Dictionary<string, string> form = new(StringComparer.Ordinal)
{
    ["grant_type"] = "client_credentials",
    ["client_id"] = "keyward-demo-service",
    ["client_secret"] = "ChangeMe!Service-Secret",
    ["scope"] = "api",
};

Console.WriteLine($"Warming up against {host}.");

for (int index = 0; index < Math.Min(concurrency * 4, 200); index++)
{
    using var warmup = new FormUrlEncodedContent(form);
    using HttpResponseMessage response = await client.PostAsync("/connect/token", warmup);

    if (response.StatusCode is not HttpStatusCode.OK)
    {
        Console.Error.WriteLine($"The endpoint answered {(int)response.StatusCode} during warm-up. Stopping.");
        return 1;
    }
}

Console.WriteLine($"Issuing {requests} tokens across {concurrency} callers.");

double[] samples = new double[requests];
int failures = 0;
int next = -1;

long started = Stopwatch.GetTimestamp();

await Parallel.ForEachAsync(
    Enumerable.Range(0, concurrency),
    new ParallelOptions { MaxDegreeOfParallelism = concurrency },
    async (_, cancellationToken) =>
    {
        while (true)
        {
            int index = Interlocked.Increment(ref next);

            if (index >= requests)
            {
                return;
            }

            long begin = Stopwatch.GetTimestamp();

            using var content = new FormUrlEncodedContent(form);
            using HttpResponseMessage response = await client.PostAsync("/connect/token", content, cancellationToken);

            samples[index] = Stopwatch.GetElapsedTime(begin).TotalMilliseconds;

            if (response.StatusCode is not HttpStatusCode.OK)
            {
                Interlocked.Increment(ref failures);
            }
        }
    });

TimeSpan elapsed = Stopwatch.GetElapsedTime(started);
Array.Sort(samples);

Console.WriteLine();
Console.WriteLine($"  requests     {requests}");
Console.WriteLine($"  failures     {failures}");
Console.WriteLine($"  wall clock   {elapsed.TotalSeconds:F2} s");
Console.WriteLine($"  throughput   {requests / elapsed.TotalSeconds:F0} tokens/s");
Console.WriteLine($"  p50          {Percentile(samples, 0.50):F2} ms");
Console.WriteLine($"  p95          {Percentile(samples, 0.95):F2} ms");
Console.WriteLine($"  p99          {Percentile(samples, 0.99):F2} ms");
Console.WriteLine($"  max          {samples[^1]:F2} ms");

return failures is 0 ? 0 : 1;

static double Percentile(double[] sorted, double quantile)
{
    int index = (int)Math.Ceiling(quantile * sorted.Length) - 1;

    return sorted[Math.Clamp(index, 0, sorted.Length - 1)];
}
