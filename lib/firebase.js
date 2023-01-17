import firebase from "firebase/compat/app";
import "firebase/compat/auth";
import "firebase/compat/firestore";
import "firebase/compat/storage";

// Import the functions you need from the SDKs you need
import { getAnalytics } from "firebase/analytics";
// TODO: Add SDKs for Firebase products that you want to use
// https://firebase.google.com/docs/web/setup#available-libraries

// Your web app's Firebase configuration
// For Firebase JS SDK v7.20.0 and later, measurementId is optional
const firebaseConfig = {
	apiKey: "AIzaSyCny0fiBRc1_p-Z5SzNcYEGjwiSZ3Ksaik",
	authDomain: "nextfire-ba64f.firebaseapp.com",
	projectId: "nextfire-ba64f",
	storageBucket: "nextfire-ba64f.appspot.com",
	messagingSenderId: "448623557092",
	appId: "1:448623557092:web:ddbf8f04299ab582a12ff1",
	measurementId: "G-H1VGWPNWK6",
};

// Initialize Firebase
if (!firebase.apps.length) {
	firebase.initializeApp(firebaseConfig);
}

export const auth = firebase.auth();
export const googleAuthProvider = new firebase.auth.GoogleAuthProvider();

export const firestore = firebase.firestore();
export const storage = firebase.storage();
export const STATE_CHANGED = firebase.storage.TaskEvent.STATE_CHANGED;
// export const analytics = getAnalytics(app);

// Helper functions

/*
 * Gets a user/{uid} document with username
 * @param  {string} username
 */
export async function getUserWithUsername(username) {
	const usersRef = firestore.collection("users");
	const query = usersRef.where("username", "==", username).limit(1);
	const userDoc = (await query.get()).docs[0];
	return userDoc;
}

/*
 * Converts a firestore document to JSON
 * @param  {DocumentSnapshot} doc
 * /
 */
export function postToJSON(doc) {
	const data = doc.data();
	return {
		...data,
		// Gotcha! firestore timestamp NOT serializable to JSON. Must convert to milliseconds
		createdAt: data.createdAt.toMillis(),
		updatedAt: data.updatedAt.toMillis(),
	};
}

export const fromMillis = firebase.firestore.Timestamp.fromMillis;
export const serverTimestamp = firebase.firestore.FieldValue.serverTimestamp;
export const increment = firebase.firestore.FieldValue.increment;
