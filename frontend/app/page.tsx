"use client"
import { useState } from 'react';

export default function Home() {
  const [url, setUrl] = useState('');
  const [results, setResults] = useState<any>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(''); 

    try {
      const response = await fetch('http://localhost:5000/scan', { 
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url }),
      });

      if (!response.ok) {
        const errorData = await response.json(); 
        throw new Error(errorData.error || 'An error occurred during the scan.');
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
    <div className="container mx-auto p-4">
      <h1 className="text-3xl font-bold mb-4">Web Security Scanner</h1>

      <form onSubmit={handleSubmit} className="mb-4">
        <input
          type="url"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="Enter URL (e.g., https://example.com)"
          className="border border-gray-300 rounded px-3 py-2 w-full mb-2 text-black"
          required
        />
        <button
          type="submit"
          className={`bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded ${loading ? 'opacity-50 cursor-not-allowed' : ''}`}
          disabled={loading} 
        >
          {loading ? (
            <div className="flex items-center justify-center">
              <svg className="animate-spin h-5 w-5 mr-3" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
              Scanning...
            </div>
          ) : (
            "Scan"
          )}
        </button>
      </form>

      {error && <p className="text-red-500">{error}</p>} {/* Display error message */}

      {results && (
        <div className="mt-4">
          <h2 className="text-2xl font-bold mb-2">Scan Results</h2>
          <p><strong>Scanned URLs:</strong></p>
          <ul className="list-disc pl-5">
            {results.scanned_urls.map((scannedUrl: string, index: number) => (
              <li key={index}>{scannedUrl}</li>
            ))}
          </ul>
          {results.vulnerabilities.length > 0 ? (
            <div>
              <p className="mt-2"><strong>Vulnerabilities Found:</strong></p>
              <ul className="list-disc pl-5">
                {results.vulnerabilities.map((vuln: any, index: number) => (
                  <li key={index} className="border border-red-500 rounded p-2 mb-2">
                    {Object.entries(vuln).map(([key, value]) => (
                      <p key={key}><strong>{key}:</strong> {String(value)}</p>
                    ))}
                  </li>
                ))}
              </ul>
            </div>
          ) : (
            <p className="mt-2">No vulnerabilities found.</p>
          )}
        </div>
      )}
    </div>
  );
}