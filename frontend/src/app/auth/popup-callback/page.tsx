'use client';

import { useEffect } from 'react';

export default function AuthPopupCallback() {
  useEffect(() => {
    // Notify the parent window that authentication is complete
    if (window.opener) {
      window.opener.postMessage({ type: 'AUTH_SUCCESS' }, window.location.origin);
      // Close this popup
      window.close();
    } else {
      // Fallback if not in a popup (e.g. user manually navigated here)
      window.location.href = '/dashboard';
    }
  }, []);

  return (
    <div className="flex min-h-screen items-center justify-center bg-gray-950 text-white">
      <div className="text-center">
        <p className="text-lg font-medium">Authentication successful.</p>
        <p className="text-sm text-gray-400">Closing window...</p>
      </div>
    </div>
  );
}
