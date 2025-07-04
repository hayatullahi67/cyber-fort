import { useState, useEffect } from "react";
import { useMutation } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { UrlCheckResult } from "@/contexts/CheckHistoryContext";
import CollapsibleHistory from "./CollapsibleHistory";

interface HistoryItem {
  id: number;
  title: string;
  subtitle: string;
  timestamp: string;
  status: "safe" | "unsafe";
}

const STORAGE_KEY = 'url_check_history';

interface CheckResult {
  url: string;
  safe: boolean;
  exists: boolean;
  safety_report: {
    stats: {
      total: number;
      malicious: number;
      suspicious: number;
      undetected: number;
    };
    risk_score: number;
    issues: string[];
    ssl_issues?: string[];
  };
  http_status: number;
  final_url: string;
  warnings: string[];
}

// Enhanced Storage Manager Class
class StorageManager {
  private storage: Storage | null = null;
  private memoryStorage: Map<string, string> = new Map();
  private isStorageAvailable: boolean = false;

  constructor() {
    this.initializeStorage();
  }

  private initializeStorage() {
    // Try localStorage first
    if (this.testStorage(window.localStorage)) {
      this.storage = window.localStorage;
      this.isStorageAvailable = true;
      console.log('✅ Using localStorage');
      return;
    }

    // Fallback to sessionStorage
    if (this.testStorage(window.sessionStorage)) {
      this.storage = window.sessionStorage;
      this.isStorageAvailable = true;
      console.log('⚠️ Using sessionStorage (localStorage unavailable)');
      return;
    }

    // Fallback to memory storage
    console.log('❌ Using memory storage (browser storage unavailable)');
    this.isStorageAvailable = false;
  }

  private testStorage(storage: Storage): boolean {
    try {
      const testKey = '__storage_test__';
      storage.setItem(testKey, 'test');
      const retrieved = storage.getItem(testKey);
      storage.removeItem(testKey);
      return retrieved === 'test';
    } catch (error) {
      console.warn('Storage test failed:', error);
      return false;
    }
  }

  public setItem(key: string, value: string): boolean {
    try {
      if (this.storage) {
        this.storage.setItem(key, value);
      } else {
        this.memoryStorage.set(key, value);
      }
      return true;
    } catch (error) {
      console.error('Error saving to storage:', error);
      
      // If storage fails, try memory storage as backup
      try {
        this.memoryStorage.set(key, value);
        return true;
      } catch (memError) {
        console.error('Memory storage also failed:', memError);
        return false;
      }
    }
  }

  public getItem(key: string): string | null {
    try {
      if (this.storage) {
        return this.storage.getItem(key);
      } else {
        return this.memoryStorage.get(key) || null;
      }
    } catch (error) {
      console.error('Error reading from storage:', error);
      return this.memoryStorage.get(key) || null;
    }
  }

  public removeItem(key: string): boolean {
    try {
      if (this.storage) {
        this.storage.removeItem(key);
      } else {
        this.memoryStorage.delete(key);
      }
      return true;
    } catch (error) {
      console.error('Error removing from storage:', error);
      return false;
    }
  }

  public isAvailable(): boolean {
    return this.isStorageAvailable || this.memoryStorage.size >= 0;
  }

  public getStorageType(): string {
    if (this.storage === window.localStorage) return 'localStorage';
    if (this.storage === window.sessionStorage) return 'sessionStorage';
    return 'memoryStorage';
  }
}

// Create global storage manager instance
const storageManager = new StorageManager();

export default function URLChecker() {
  const [url, setUrl] = useState("");
  const [urlHistory, setUrlHistory] = useState<UrlCheckResult[]>([]);
  const [storageStatus, setStorageStatus] = useState<string>("");
  const [checkResult, setCheckResult] = useState<CheckResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Enhanced function to load history from storage
  const loadHistoryFromStorage = (): UrlCheckResult[] => {
    try {
      const savedHistory = storageManager.getItem(STORAGE_KEY);
      if (savedHistory && savedHistory.trim() !== '' && savedHistory !== 'null') {
        const parsed = JSON.parse(savedHistory);
        if (Array.isArray(parsed)) {
          console.log(`📁 Loaded ${parsed.length} items from ${storageManager.getStorageType()}`);
          return parsed;
        }
      }
    } catch (error) {
      console.error('Error parsing saved history:', error);
    }
    return [];
  };

  // Enhanced function to save history to storage
  const saveHistoryToStorage = (history: UrlCheckResult[]): boolean => {
    try {
      const success = storageManager.setItem(STORAGE_KEY, JSON.stringify(history));
      if (success) {
        console.log(`💾 Saved ${history.length} items to ${storageManager.getStorageType()}`);
      }
      return success;
    } catch (error) {
      console.error('Error saving history:', error);
      return false;
    }
  };

  // Load history from storage on component mount
  useEffect(() => {
    const loadedHistory = loadHistoryFromStorage();
    setUrlHistory(loadedHistory);
    setStorageStatus(`Using: ${storageManager.getStorageType()}`);
    
    // Debug info for mobile troubleshooting
    console.log('🔍 Storage Debug Info:', {
      storageType: storageManager.getStorageType(),
      isAvailable: storageManager.isAvailable(),
      loadedItems: loadedHistory.length,
      userAgent: navigator.userAgent,
      screenWidth: window.innerWidth,
      isPrivateMode: !storageManager.isAvailable()
    });
  }, []);

  // Save history to storage whenever it changes (with debouncing)
  useEffect(() => {
    if (urlHistory.length > 0) {
      const success = saveHistoryToStorage(urlHistory);
      if (!success) {
        console.warn('Failed to save history to storage');
      }
    }
  }, [urlHistory]);

  // URL check mutation
  const checkUrlMutation = useMutation({
    mutationFn: async (urlToCheck: string) => {
      const response = await apiRequest(
        "POST",
        "/api/check-url",
        { url: urlToCheck }
      );

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || "Failed to check URL");
      }

      return response.json();
    },
    onSuccess: (data) => {
      setError(null);
      setCheckResult(data);
      
      // Add to history
      const historyItem: UrlCheckResult = {
        id: Date.now(),
        url: data.url,
        isSafe: data.safe,
        result: data.exists 
          ? (data.safe ? "Safe - No threats detected" : `Dangerous - ${data.safety_report.issues.join(", ")}`)
          : "URL does not exist",
        checkedAt: new Date().toISOString()
      };
      
      setUrlHistory(prev => [historyItem, ...prev].slice(0, 10));
    },
    onError: (error: Error) => {
      setError(error.message);
      setCheckResult(null);
    }
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!url) return;
    checkUrlMutation.mutate(url);
  };

  // Clear history function
  const clearHistory = () => {
    setUrlHistory([]);
    storageManager.removeItem(STORAGE_KEY);
    console.log('🗑️ History cleared');
  };

  // Test storage function for debugging
  const testStorage = () => {
    const testData = {
      id: Date.now(),
      test: 'Mobile storage test',
      timestamp: new Date().toISOString()
    };
    
    const success = storageManager.setItem('test_key', JSON.stringify(testData));
    const retrieved = storageManager.getItem('test_key');
    
    const message = `Storage Test Results:
    - Type: ${storageManager.getStorageType()}
    - Save Success: ${success}
    - Retrieve Success: ${retrieved !== null}
    - Data Match: ${retrieved === JSON.stringify(testData)}
    - Browser: ${navigator.userAgent.includes('Mobile') ? 'Mobile' : 'Desktop'}`;
    
    alert(message);
    console.log('🧪 Storage Test:', { success, retrieved, testData });
    
    // Cleanup
    storageManager.removeItem('test_key');
  };

  // Format history items for CollapsibleHistory component
  const historyItems: HistoryItem[] = urlHistory.map(item => ({
    id: item.id,
    title: item.url,
    subtitle: item.isSafe ? "Safe - No threats detected" : `Dangerous - ${item.result}`,
    timestamp: item.checkedAt,
    status: item.isSafe ? "safe" as const : "unsafe" as const
  }));

  return (
    <Card className="bg-white dark:bg-gray-800">
      <CardContent className="p-6">
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-xl font-semibold text-gray-800 dark:text-white">URL Checker</h2>
          <div className="text-xs text-gray-500 dark:text-gray-400">
            {storageStatus}
          </div>
        </div>

        <form onSubmit={handleSubmit} className="mb-4">
          <div className="mb-4">
            <Label htmlFor="url-input" className="block text-sm font-medium mb-1 text-gray-700 dark:text-gray-300">
              Enter URL to check
            </Label>
            <div className="flex">
              <Input
                id="url-input"
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://example.com"
                className="rounded-r-none bg-white dark:bg-gray-700 outline-none focus:outline-none focus:ring-0 focus-visible:outline-none focus-visible:ring-0"
              />
              <Button 
                type="submit" 
                className="rounded-l-none"
                disabled={checkUrlMutation.isPending}
              >
                {checkUrlMutation.isPending ? "Checking..." : "Check"}
              </Button>
            </div>
          </div>
        </form>

        {/* Debug buttons - remove in production */}
        <div className="mb-4 flex gap-2">
          {/* <Button 
            onClick={testStorage} 
            variant="outline" 
            size="sm"
            className="text-xs"
          >
            Test Storage
          </Button> */}
          <Button 
            onClick={clearHistory} 
            variant="outline" 
            size="sm"
            className="text-xs"
            disabled={urlHistory.length === 0}
          >
            Clear History ({urlHistory.length})
          </Button>
        </div>

        {/* Result Display */}
        {checkUrlMutation.isPending && (
          <div className="mb-6 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
            <div className="flex items-center justify-center p-2">
              <div className="animate-spin h-5 w-5 border-2 border-blue-500 rounded-full border-t-transparent"></div>
              <span className="ml-2 text-gray-700 dark:text-gray-300">Checking URL...</span>
            </div>
          </div>
        )}

        {!checkUrlMutation.isPending && error && (
          <div className="mb-6 p-4 rounded-lg border border-red-500 bg-red-50 dark:bg-red-900/20">
            <div className="flex">
              <div className="flex-shrink-0">
                <svg className="h-5 w-5 text-red-500 dark:text-red-300" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                </svg>
              </div>
              <div className="ml-3">
                <h3 className="text-sm font-medium text-red-800 dark:text-red-300">Error</h3>
                <div className="mt-2 text-sm text-red-700 dark:text-red-400">
                  <p>{error}</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {!checkUrlMutation.isPending && checkResult && (
          <div className="mb-6 space-y-4">
            {/* URL Existence Status */}
            <div className={`p-4 rounded-lg border ${
              checkResult.exists ? "border-green-500" : "border-red-500"
            }`}>
              <div className="flex">
                <div className="flex-shrink-0">
                  <span className={`inline-flex items-center justify-center h-8 w-8 rounded-full ${
                    checkResult.exists ? "bg-green-100 dark:bg-green-900" : "bg-red-100 dark:bg-red-900"
                  }`}>
                    {checkResult.exists ? (
                      <svg className="h-5 w-5 text-green-500 dark:text-green-300" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                        <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                      </svg>
                    ) : (
                      <svg className="h-5 w-5 text-red-500 dark:text-red-300" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                        <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                      </svg>
                    )}
                  </span>
                </div>
                <div className="ml-3">
                  <h3 className={`text-sm font-medium ${
                    checkResult.exists ? "text-green-800 dark:text-green-300" : "text-red-800 dark:text-red-300"
                  }`}>
                    {checkResult.exists ? "URL Exists" : "URL Does Not Exist"}
                  </h3>
                  <div className={`mt-2 text-sm ${
                    checkResult.exists ? "text-green-700 dark:text-green-400" : "text-red-700 dark:text-red-400"
                  }`}>
                    <p>
                      {checkResult.exists 
                        ? `The URL is accessible (HTTP Status: ${checkResult.http_status})`
                        : "The URL could not be reached. It may be down or invalid."
                      }
                    </p>
                    {checkResult.warnings && checkResult.warnings.length > 0 && (
                      <ul className="mt-2 list-disc list-inside">
                        {checkResult.warnings.map((warning, index) => (
                          <li key={index}>{warning}</li>
                        ))}
                      </ul>
                    )}
                  </div>
                </div>
              </div>
            </div>

            {/* Safety Status */}
            {checkResult.exists && (
              <div className={`p-4 rounded-lg border ${
                checkResult.safe ? "border-green-500" : "border-red-500"
              }`}>
                <div className="flex">
                  <div className="flex-shrink-0">
                    <span className={`inline-flex items-center justify-center h-8 w-8 rounded-full ${
                      checkResult.safe ? "bg-green-100 dark:bg-green-900" : "bg-red-100 dark:bg-red-900"
                    }`}>
                      {checkResult.safe ? (
                        <svg className="h-5 w-5 text-green-500 dark:text-green-300" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                          <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                        </svg>
                      ) : (
                        <svg className="h-5 w-5 text-red-500 dark:text-red-300" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                          <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                        </svg>
                      )}
                    </span>
                  </div>
                  <div className="ml-3">
                    <h3 className={`text-sm font-medium ${
                      checkResult.safe ? "text-green-800 dark:text-green-300" : "text-red-800 dark:text-red-300"
                    }`}>
                      {checkResult.safe ? "Safe URL" : "Dangerous URL"}
                    </h3>
                    <div className={`mt-2 text-sm ${
                      checkResult.safe ? "text-green-700 dark:text-green-400" : "text-red-700 dark:text-red-400"
                    }`}>
                      <p>
                        {checkResult.safe 
                          ? "No malicious content or suspicious patterns detected"
                          : "This URL shows signs of being malicious or compromised"
                        }
                      </p>
                      {checkResult.safety_report.issues && checkResult.safety_report.issues.length > 0 && (
                        <ul className="mt-2 list-disc list-inside">
                          {checkResult.safety_report.issues.map((issue, index) => (
                            <li key={index}>{issue}</li>
                          ))}
                        </ul>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* SSL Certificate Warning */}
            {checkResult.exists && checkResult.safety_report.ssl_issues && checkResult.safety_report.ssl_issues.length > 0 && (
              <div className="p-4 rounded-lg border border-yellow-500 bg-yellow-50 dark:bg-yellow-900/20">
                <div className="flex">
                  <div className="flex-shrink-0">
                    <svg className="h-5 w-5 text-yellow-400 dark:text-yellow-300" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                      <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                    </svg>
                  </div>
                  <div className="ml-3">
                    <h3 className="text-sm font-medium text-yellow-800 dark:text-yellow-300">SSL Certificate Warning</h3>
                    <div className="mt-2 text-sm text-yellow-700 dark:text-yellow-400">
                      <p>⚠️ Potential SSL Issue: The website's security certificate may be expired, misconfigured, or untrusted. Proceed with caution.</p>
                      <ul className="mt-2 list-disc list-inside">
                        {checkResult.safety_report.ssl_issues.map((issue, index) => (
                          <li key={index}>{issue}</li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* URL History */}
        <CollapsibleHistory 
          title="URL History" 
          items={historyItems}
        />
      </CardContent>
    </Card>
  );
}