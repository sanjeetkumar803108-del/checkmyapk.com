/// <reference types="vite/client" />
import { initializeApp, getApps, getApp } from 'firebase/app';
import { getAuth, GoogleAuthProvider, signInWithPopup } from 'firebase/auth';

const firebaseConfig = {
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY || '',
  authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN || '',
  projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID || '',
  appId: import.meta.env.VITE_FIREBASE_APP_ID || '',
};

export function isFirebaseGoogleConfigured(): boolean {
  return Boolean(
    firebaseConfig.apiKey.trim() &&
      firebaseConfig.authDomain.trim() &&
      firebaseConfig.projectId.trim()
  );
}

export async function signInWithGooglePopup(): Promise<{ idToken: string }> {
  if (!isFirebaseGoogleConfigured()) {
    throw new Error('FIREBASE_NOT_CONFIGURED');
  }

  const app = getApps().length > 0 ? getApp() : initializeApp(firebaseConfig);
  const auth = getAuth(app);
  const provider = new GoogleAuthProvider();
  provider.setCustomParameters({ prompt: 'select_account' });

  const credential = await signInWithPopup(auth, provider);
  const idToken = await credential.user.getIdToken();
  return { idToken };
}
