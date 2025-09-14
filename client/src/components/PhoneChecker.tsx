// import { useState, useEffect } from "react";
// import { useMutation } from "@tanstack/react-query";
// import { apiRequest } from "@/lib/queryClient";
// import { Card, CardContent } from "@/components/ui/card";
// import { Input } from "@/components/ui/input";
// import { Button } from "@/components/ui/button";
// import { Label } from "@/components/ui/label";
// import { PhoneCheckResult } from "@/contexts/CheckHistoryContext";
// import CollapsibleHistory from "./CollapsibleHistory";
// import axios from "axios";

// interface HistoryItem {
//   id: number;
//   title: string;
//   subtitle: string;
//   timestamp: string;
//   status: "safe" | "unsafe";
// }

// const STORAGE_KEY = 'phone_check_history';

// export default function PhoneChecker() {
//   const [phoneNumber, setPhoneNumber] = useState("");
//   const [phoneHistory, setPhoneHistory] = useState<PhoneCheckResult[]>([]);
//   const [checkResult, setCheckResult] = useState<{
//     phoneNumber: string;
//     isSafe: boolean;
//     country: string;
//     carrier: string;
//     lineType: string;
//     riskScore: number;
//     details?: any;
//   } | null>(null);
//   const [error, setError] = useState<string | null>(null);

//   // Load history from localStorage on component mount
//   useEffect(() => {
//     const savedHistory = localStorage.getItem(STORAGE_KEY);
//     if (savedHistory) {
//       setPhoneHistory(JSON.parse(savedHistory));
//     }
//   }, []);

//   // Save history to localStorage whenever it changes
//   useEffect(() => {
//     localStorage.setItem(STORAGE_KEY, JSON.stringify(phoneHistory));
//   }, [phoneHistory]);

//   // Phone check mutation
//   const checkPhoneMutation = useMutation({
//     mutationFn: async (phoneToCheck: string) => {
//       // Format number for API
//       let formattedNumber = phoneToCheck;
//       if (!phoneToCheck.startsWith('+')) {
//         formattedNumber = `+${phoneToCheck}`;
//       }

//       // Call Abstract API directly
//       const response = await axios.get(
//         `https://phonevalidation.abstractapi.com/v1/?api_key=584345ac18d143e6aab67270331031d7&phone=${encodeURIComponent(formattedNumber)}`
//       );

//       const data = response.data;

//       // Calculate risk score
//       let riskScore = 0;
//       if (!data.valid) riskScore += 70;
//       if (data.type === "voip") riskScore += 30;
//       riskScore = Math.min(riskScore, 100);

//       // Determine if safe
//       const isSafe = riskScore < 50;

//       // Format response
//       return {
//         phoneNumber: formattedNumber,
//         isSafe,
//         country: data.country?.name || "Unknown",
//         carrier: data.carrier || "Unknown",
//         lineType: data.type || "Unknown",
//         riskScore,
//         details: {
//           valid: data.valid,
//           formatted: data.format?.international || formattedNumber,
//           location: data.location || "",
//           spamReports: 0
//         }
//       };
//     },
//     onSuccess: (data) => {
//       setError(null);
//       setCheckResult(data);
      
//       // Add to history
//       const historyItem: PhoneCheckResult = {
//         id: Date.now(),
//         phoneNumber: data.phoneNumber,
//         isSafe: data.isSafe,
//         country: data.country,
//         carrier: data.carrier,
//         lineType: data.lineType,
//         riskScore: data.riskScore,
//         checkedAt: new Date().toISOString()
//       };
      
//       setPhoneHistory(prev => [historyItem, ...prev].slice(0, 10));
//     },
//     onError: (error: Error) => {
//       setError(error.message);
//       setCheckResult(null);
//     }
//   });

//   const handleSubmit = (e: React.FormEvent) => {
//     e.preventDefault();
//     if (!phoneNumber) return;
    
//     checkPhoneMutation.mutate(phoneNumber);
//   };

//   // Format history items for CollapsibleHistory component
//   const historyItems = phoneHistory.map(item => ({
//     id: item.id,
//     title: item.phoneNumber,
//     subtitle: item.isSafe 
//       ? `Safe - ${item.country}, ${item.carrier}` 
//       : `Suspicious - Potential spam (${item.riskScore}% risk)`,
//     timestamp: item.checkedAt,
//     status: item.isSafe ? "safe" : "unsafe"
//   } as const)) as unknown as HistoryItem[];

//   return (
//     <Card className="bg-white dark:bg-gray-800">
//       <CardContent className="p-6">
//         <h2 className="text-xl font-semibold mb-4 text-gray-800 dark:text-white">Phone Number Checker</h2>
        
//         <form onSubmit={handleSubmit} className="mb-4">
//           <div className="mb-4">
//             <Label htmlFor="phone-input" className="block text-sm font-medium mb-1 text-gray-700 dark:text-gray-300">
//               Enter phone number to check
//             </Label>
//             <div className="flex">
//               <Input
//                 id="phone-input"
//                 type="tel"
//                 value={phoneNumber}
//                 onChange={(e) => setPhoneNumber(e.target.value)}
//                 placeholder="+1 (555) 123-4567"
//                 className="rounded-r-none bg-white dark:bg-gray-700 outline-none  focus:outline-none focus:ring-0 focus-visible:outline-none focus-visible:ring-0"
//               />
//               <Button 
//                 type="submit" 
//                 className="rounded-l-none"
//                 disabled={checkPhoneMutation.isPending}
//               >
//                 {checkPhoneMutation.isPending ? "Checking..." : "Check"}
//               </Button>
//             </div>
//           </div>
//         </form>

//         {/* Result Display */}
//         {checkPhoneMutation.isPending && (
//           <div className="mb-6 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
//             <div className="flex items-center justify-center p-2">
//               <div className="animate-spin h-5 w-5 border-2 border-blue-500 rounded-full border-t-transparent"></div>
//               <span className="ml-2 text-gray-700 dark:text-gray-300">Checking phone number...</span>
//             </div>
//           </div>
//         )}
        
//         {!checkPhoneMutation.isPending && error && (
//           <div className="mb-6 p-4 rounded-lg border border-red-500 bg-red-50 dark:bg-red-900/20">
//             <div className="flex">
//               <div className="flex-shrink-0">
//                 <svg className="h-5 w-5 text-red-500 dark:text-red-300" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
//                   <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
//                 </svg>
//               </div>
//               <div className="ml-3">
//                 <h3 className="text-sm font-medium text-red-800 dark:text-red-300">Error</h3>
//                 <div className="mt-2 text-sm text-red-700 dark:text-red-400">
//                   <p>{error}</p>
//                   <p className="mt-1">Please try again or use a different phone number.</p>
//                 </div>
//               </div>
//             </div>
//           </div>
//         )}

//         {!checkPhoneMutation.isPending && checkResult && (
//           <div className={`mb-6 p-4 rounded-lg border ${
//             checkResult.isSafe ? "border-green-500" : "border-red-500"
//           }`}>
//             <div className="flex">
//               <div className="flex-shrink-0">
//                 <span className={`inline-flex items-center justify-center h-8 w-8 rounded-full ${
//                   checkResult.isSafe ? "bg-green-100 dark:bg-green-900" : "bg-red-100 dark:bg-red-900"
//                 }`}>
//                   {checkResult.isSafe ? (
//                     <svg className="h-5 w-5 text-green-500 dark:text-green-300" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
//                       <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
//                     </svg>
//                   ) : (
//                     <svg className="h-5 w-5 text-red-500 dark:text-red-300" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
//                       <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
//                     </svg>
//                   )}
//                 </span>
//               </div>
//               <div className="ml-3">
//                 <h3 className={`text-sm font-medium ${
//                   checkResult.isSafe ? "text-green-800 dark:text-green-300" : "text-red-800 dark:text-red-300"
//                 }`}>
//                   {checkResult.isSafe ? "Safe Phone Number" : "Suspicious Phone Number"}
//                 </h3>
//                 <div className={`mt-2 text-sm ${
//                   checkResult.isSafe ? "text-green-700 dark:text-green-400" : "text-red-700 dark:text-red-400"
//                 }`}>
//                   <p>
//                     {checkResult.isSafe 
//                       ? "No suspicious activity detected with this number."
//                       : "This number has been flagged for potential spam or scam activity."
//                     }
//                   </p>
//                 </div>
//                 <div className="mt-3">
//                   <dl className="grid grid-cols-1 gap-x-4 gap-y-2 sm:grid-cols-2">
//                     <div className="sm:col-span-1">
//                       <dt className="text-xs font-medium text-gray-500 dark:text-gray-400">Country</dt>
//                       <dd className="mt-1 text-sm text-gray-900 dark:text-white">{checkResult.country}</dd>
//                     </div>
//                     <div className="sm:col-span-1">
//                       <dt className="text-xs font-medium text-gray-500 dark:text-gray-400">Carrier</dt>
//                       <dd className="mt-1 text-sm text-gray-900 dark:text-white">{checkResult.carrier}</dd>
//                     </div>
//                     <div className="sm:col-span-1">
//                       <dt className="text-xs font-medium text-gray-500 dark:text-gray-400">Risk Score</dt>
//                       <dd className="mt-1 text-sm text-gray-900 dark:text-white">
//                         {checkResult.riskScore}/100 ({checkResult.riskScore < 50 ? "Low" : "High"} Risk)
//                       </dd>
//                     </div>
//                     <div className="sm:col-span-1">
//                       <dt className="text-xs font-medium text-gray-500 dark:text-gray-400">Line Type</dt>
//                       <dd className="mt-1 text-sm text-gray-900 dark:text-white">{checkResult.lineType}</dd>
//                     </div>
//                     {!checkResult.isSafe && checkResult.details?.spamReports > 0 && (
//                       <div className="sm:col-span-1">
//                         <dt className="text-xs font-medium text-gray-500 dark:text-gray-400">Reports</dt>
//                         <dd className="mt-1 text-sm text-gray-900 dark:text-white">
//                           {checkResult.details.spamReports} spam reports
//                         </dd>
//                       </div>
//                     )}
//                   </dl>
//                 </div>
//               </div>
//             </div>
//           </div>
//         )}

//         {/* Phone History */}
//         <CollapsibleHistory 
//           title="Phone History" 
//           items={historyItems}
//         />
//       </CardContent>
//     </Card>
//   );
// }













import { useState, useEffect } from "react";
import { useMutation } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { PhoneCheckResult } from "@/contexts/CheckHistoryContext";
import CollapsibleHistory from "./CollapsibleHistory";
import axios from "axios";

interface HistoryItem {
  id: number;
  title: string;
  subtitle: string;
  timestamp: string;
  status: "safe" | "unsafe";
}

const STORAGE_KEY = 'phone_check_history';

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

export default function PhoneChecker() {
  const [phoneNumber, setPhoneNumber] = useState("");
  const [phoneHistory, setPhoneHistory] = useState<PhoneCheckResult[]>([]);
  const [storageStatus, setStorageStatus] = useState<string>("");
  const [checkResult, setCheckResult] = useState<{
    phoneNumber: string;
    isSafe: boolean;
    country: string;
    carrier: string;
    lineType: string;
    riskScore: number;
    details?: any;
  } | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Enhanced function to load history from storage
  const loadHistoryFromStorage = (): PhoneCheckResult[] => {
    try {
      const savedHistory = storageManager.getItem(STORAGE_KEY);
      if (savedHistory && savedHistory.trim() !== '' && savedHistory !== 'null') {
        const parsed = JSON.parse(savedHistory);
        if (Array.isArray(parsed)) {
          console.log(`📁 Loaded ${parsed.length} phone items from ${storageManager.getStorageType()}`);
          return parsed;
        }
      }
    } catch (error) {
      console.error('Error parsing saved phone history:', error);
    }
    return [];
  };

  // Enhanced function to save history to storage
  const saveHistoryToStorage = (history: PhoneCheckResult[]): boolean => {
    try {
      const success = storageManager.setItem(STORAGE_KEY, JSON.stringify(history));
      if (success) {
        console.log(`💾 Saved ${history.length} phone items to ${storageManager.getStorageType()}`);
      }
      return success;
    } catch (error) {
      console.error('Error saving phone history:', error);
      return false;
    }
  };

  // Load history from storage on component mount
  useEffect(() => {
    const loadedHistory = loadHistoryFromStorage();
    setPhoneHistory(loadedHistory);
    setStorageStatus(`Using: ${storageManager.getStorageType()}`);
    
    // Debug info for mobile troubleshooting
    console.log('🔍 Phone Storage Debug Info:', {
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
    if (phoneHistory.length > 0) {
      const success = saveHistoryToStorage(phoneHistory);
      if (!success) {
        console.warn('Failed to save phone history to storage');
      }
    }
  }, [phoneHistory]);

  // Phone check mutation
  const checkPhoneMutation = useMutation({
    mutationFn: async (phoneToCheck: string) => {
      // Format number for API
      let formattedNumber = phoneToCheck;
      if (!phoneToCheck.startsWith('+')) {
        formattedNumber = `+${phoneToCheck}`;
      }

      // Call Abstract API directly
      const response = await axios.get(
        `https://phonevalidation.abstractapi.com/v1/?api_key=584345ac18d143e6aab67270331031d7&phone=${encodeURIComponent(formattedNumber)}`
      );

      const data = response.data;

      // Calculate risk score
      let riskScore = 0;
      if (!data.valid) riskScore += 70;
      if (data.type === "voip") riskScore += 30;
      riskScore = Math.min(riskScore, 100);

      // Determine if safe
      const isSafe = riskScore < 50;

      // Format response
      return {
        phoneNumber: formattedNumber,
        isSafe,
        country: data.country?.name || "Unknown",
        carrier: data.carrier || "Unknown",
        lineType: data.type || "Unknown",
        riskScore,
        details: {
          valid: data.valid,
          formatted: data.format?.international || formattedNumber,
          location: data.location || "",
          spamReports: 0
        }
      };
    },
    onSuccess: (data) => {
      setError(null);
      setCheckResult(data);
      
      // Add to history
      const historyItem: PhoneCheckResult = {
        id: Date.now(),
        phoneNumber: data.phoneNumber,
        isSafe: data.isSafe,
        country: data.country,
        carrier: data.carrier,
        lineType: data.lineType,
        riskScore: data.riskScore,
        checkedAt: new Date().toISOString()
      };
      
      // Update history (keep last 10 items)
      setPhoneHistory(prev => {
        const newHistory = [historyItem, ...prev];
        return newHistory;
      });
    },
    onError: (error: Error) => {
      setError(error.message);
      setCheckResult(null);
    }
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!phoneNumber) return;
    
    checkPhoneMutation.mutate(phoneNumber);
  };

  // Clear history function
  const clearHistory = () => {
    setPhoneHistory([]);
    storageManager.removeItem(STORAGE_KEY);
    console.log('🗑️ Phone history cleared');
  };

  // Test storage function for debugging
  const testStorage = () => {
    const testData = {
      id: Date.now(),
      test: 'Mobile phone storage test',
      timestamp: new Date().toISOString()
    };
    
    const success = storageManager.setItem('test_phone_key', JSON.stringify(testData));
    const retrieved = storageManager.getItem('test_phone_key');
    
    const message = `Phone Storage Test Results:
    - Type: ${storageManager.getStorageType()}
    - Save Success: ${success}
    - Retrieve Success: ${retrieved !== null}
    - Data Match: ${retrieved === JSON.stringify(testData)}
    - Browser: ${navigator.userAgent.includes('Mobile') ? 'Mobile' : 'Desktop'}`;
    
    alert(message);
    console.log('🧪 Phone Storage Test:', { success, retrieved, testData });
    
    // Cleanup
    storageManager.removeItem('test_phone_key');
  };

  // Format history items for CollapsibleHistory component
  const historyItems = phoneHistory.map(item => ({
    id: item.id,
    title: item.phoneNumber,
    subtitle: item.isSafe 
      ? `Safe - ${item.country}, ${item.carrier}` 
      : `Suspicious - Potential spam (${item.riskScore}% risk)`,
    timestamp: item.checkedAt,
    status: item.isSafe ? "safe" : "unsafe"
  } as const)) as unknown as HistoryItem[];

  return (
    <Card className="bg-white dark:bg-gray-800">
      <CardContent className="p-6">
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-xl font-semibold text-gray-800 dark:text-white">Phone Number Checker</h2>
          <div className="text-xs text-gray-500 dark:text-gray-400">
            {/* {storageStatus} */}
          </div>
        </div>
        
        <form onSubmit={handleSubmit} className="mb-4">
          <div className="mb-4">
            <Label htmlFor="phone-input" className="block text-sm font-medium mb-1 text-gray-700 dark:text-gray-300">
              Enter your phone number (include your country code, e.g., +1, +234, etc.).
            </Label>
            <div className="flex">
              <Input
                id="phone-input"
                type="tel"
                value={phoneNumber}
                onChange={(e) => setPhoneNumber(e.target.value)}
                placeholder="+1 (555) 123-4567"
                className="rounded-r-none bg-white dark:bg-gray-700 outline-none focus:outline-none focus:ring-0 focus-visible:outline-none focus-visible:ring-0"
              />
              <Button 
                type="submit" 
                className="rounded-l-none"
                disabled={checkPhoneMutation.isPending}
              >
                {checkPhoneMutation.isPending ? "Checking..." : "Check"}
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
            disabled={phoneHistory.length === 0}
          >
            Clear History ({phoneHistory.length})
          </Button>
        </div>

        {/* Result Display */}
        {checkPhoneMutation.isPending && (
          <div className="mb-6 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
            <div className="flex items-center justify-center p-2">
              <div className="animate-spin h-5 w-5 border-2 border-blue-500 rounded-full border-t-transparent"></div>
              <span className="ml-2 text-gray-700 dark:text-gray-300">Checking phone number...</span>
            </div>
          </div>
        )}
        
        {!checkPhoneMutation.isPending && error && (
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
                  <p className="mt-1">Please try again or use a different phone number.</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {!checkPhoneMutation.isPending && checkResult && (
          <div className={`mb-6 p-4 rounded-lg border ${
            checkResult.isSafe ? "border-green-500" : "border-red-500"
          }`}>
            <div className="flex">
              <div className="flex-shrink-0">
                <span className={`inline-flex items-center justify-center h-8 w-8 rounded-full ${
                  checkResult.isSafe ? "bg-green-100 dark:bg-green-900" : "bg-red-100 dark:bg-red-900"
                }`}>
                  {checkResult.isSafe ? (
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
                  checkResult.isSafe ? "text-green-800 dark:text-green-300" : "text-red-800 dark:text-red-300"
                }`}>
                  {checkResult.isSafe ? "Safe Phone Number" : "Suspicious Phone Number"}
                </h3>
                <div className={`mt-2 text-sm ${
                  checkResult.isSafe ? "text-green-700 dark:text-green-400" : "text-red-700 dark:text-red-400"
                }`}>
                  <p>
                    {checkResult.isSafe 
                      ? "No suspicious activity detected with this number."
                      : "This number has been flagged for potential spam or scam activity."
                    }
                  </p>
                </div>
                <div className="mt-3">
                  <dl className="grid grid-cols-1 gap-x-4 gap-y-2 sm:grid-cols-2">
                    <div className="sm:col-span-1">
                      <dt className="text-xs font-medium text-gray-500 dark:text-gray-400">Country</dt>
                      <dd className="mt-1 text-sm text-gray-900 dark:text-white">{checkResult.country}</dd>
                    </div>
                    <div className="sm:col-span-1">
                      <dt className="text-xs font-medium text-gray-500 dark:text-gray-400">Carrier</dt>
                      <dd className="mt-1 text-sm text-gray-900 dark:text-white">{checkResult.carrier}</dd>
                    </div>
                    <div className="sm:col-span-1">
                      <dt className="text-xs font-medium text-gray-500 dark:text-gray-400">Risk Score</dt>
                      <dd className="mt-1 text-sm text-gray-900 dark:text-white">
                        {checkResult.riskScore}/100 ({checkResult.riskScore < 50 ? "Low" : "High"} Risk)
                      </dd>
                    </div>
                    <div className="sm:col-span-1">
                      <dt className="text-xs font-medium text-gray-500 dark:text-gray-400">Line Type</dt>
                      <dd className="mt-1 text-sm text-gray-900 dark:text-white">{checkResult.lineType}</dd>
                    </div>
                    {!checkResult.isSafe && checkResult.details?.spamReports > 0 && (
                      <div className="sm:col-span-1">
                        <dt className="text-xs font-medium text-gray-500 dark:text-gray-400">Reports</dt>
                        <dd className="mt-1 text-sm text-gray-900 dark:text-white">
                          {checkResult.details.spamReports} spam reports
                        </dd>
                      </div>
                    )}
                  </dl>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Phone History */}
        <CollapsibleHistory 
          title="Phone History" 
          items={historyItems}
        />
      </CardContent>
    </Card>
  );
}