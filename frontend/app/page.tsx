"use client";
import { useState } from "react";

export default function Home() {
  const [url, setUrl] = useState("");
  const [results, setResults] = useState<any>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError("");

    try {
      const response = await fetch(
        "https://websitethreatscan.onrender.com/scan",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url }),
        }
      );

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(
          errorData.error || "An error occurred during the scan."
        );
      }

      const data = await response.json();
      setResults(data);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="min-h-screen bg-gradient-to-b from-gray-900 to-black">
      <div className="container mx-auto px-4 py-16 max-w-3xl">
        {/* Hero Section */}
        <div className="text-center space-y-3 mb-16">
          <h1 className="text-4xl font-bold text-white">
            Web Security Scanner
          </h1>
          <p className="text-gray-400">
            Analyze your website for security vulnerabilities
          </p>
        </div>

        {/* Search Form */}
        <form onSubmit={handleSubmit} className="mb-12">
          <div className="relative">
            <input
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="Enter website URL"
              className="w-full px-4 py-3 bg-gray-800/50 rounded-lg border border-gray-700 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all outline-none text-gray-100 placeholder:text-gray-500"
              required
            />
            <button
              type="submit"
              disabled={loading}
              className="absolute right-2 top-1/2 -translate-y-1/2 px-4 py-1.5 bg-blue-500 text-white rounded-md hover:bg-blue-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed text-sm font-medium"
            >
              {loading ? "Scanning..." : "Scan"}
            </button>
          </div>
        </form>

        {/* Error Message */}
        {error && (
          <div className="mb-8 p-3 bg-red-500/10 border border-red-500/20 rounded-lg">
            <p className="text-red-400 text-sm text-center">{error}</p>
          </div>
        )}

        {/* Results Section */}
        {results && (
          <div className="space-y-6">
            {/* Scanned URLs */}
            <div className="bg-gray-800/30 rounded-lg p-4">
              <h3 className="text-sm font-medium text-gray-400 mb-3">
                Scanned URLs ({results.scanned_urls.length})
              </h3>
              <ul className="space-y-2">
                {results.scanned_urls.map(
                  (scannedUrl: string, index: number) => (
                    <li
                      key={index}
                      className="text-sm font-mono text-gray-300 break-all bg-gray-800/30 p-2 rounded"
                    >
                      {scannedUrl}
                    </li>
                  )
                )}
              </ul>
            </div>

            {/* Vulnerabilities */}
            {results.vulnerabilities.length > 0 ? (
              <div className="space-y-4">
                <h3 className="text-sm font-medium text-red-400">
                  {results.vulnerabilities.length} Vulnerabilities Found
                </h3>
                {results.vulnerabilities.map((vuln: any, index: number) => (
                  <div
                    key={index}
                    className="bg-red-500/5 border border-red-500/10 rounded-lg p-4 hover:bg-red-500/10 transition-colors"
                  >
                    <h4 className="text-red-400 font-medium mb-3">
                      {vuln.type}
                    </h4>
                    <div className="space-y-2">
                      {Object.entries(vuln).map(([key, value]) => {
                        if (key === "type") return null;
                        return (
                          <div
                            key={key}
                            className="grid grid-cols-[100px,1fr] gap-3"
                          >
                            <span className="text-xs font-medium text-gray-500 capitalize">
                              {key.replace("_", " ")}
                            </span>
                            <code className="text-xs text-red-300 bg-red-500/10 p-1.5 rounded break-all">
                              {String(value)}
                            </code>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="bg-emerald-500/5 border border-emerald-500/10 rounded-lg p-4">
                <p className="text-emerald-400 text-sm font-medium">
                  {results.message || "No vulnerabilities found"}
                </p>
              </div>
            )}
          </div>
        )}
      </div>
    </main>
  );
}
