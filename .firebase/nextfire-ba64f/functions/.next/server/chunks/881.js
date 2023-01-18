"use strict";
exports.id = 881;
exports.ids = [881];
exports.modules = {

/***/ 2881:
/***/ ((module, __webpack_exports__, __webpack_require__) => {

__webpack_require__.a(module, async (__webpack_handle_async_dependencies__, __webpack_async_result__) => { try {
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "Bt": () => (/* binding */ serverTimestamp),
/* harmony export */   "I8": () => (/* binding */ auth),
/* harmony export */   "Lg": () => (/* binding */ fromMillis),
/* harmony export */   "Lp": () => (/* binding */ getUserWithUsername),
/* harmony export */   "RZ": () => (/* binding */ firestore),
/* harmony export */   "WS": () => (/* binding */ postToJSON),
/* harmony export */   "mC": () => (/* binding */ STATE_CHANGED),
/* harmony export */   "nP": () => (/* binding */ increment),
/* harmony export */   "qV": () => (/* binding */ googleAuthProvider),
/* harmony export */   "tO": () => (/* binding */ storage)
/* harmony export */ });
/* harmony import */ var firebase_compat_app__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(3773);
/* harmony import */ var firebase_compat_auth__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(4826);
/* harmony import */ var firebase_compat_firestore__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(741);
/* harmony import */ var firebase_compat_storage__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(451);
/* harmony import */ var firebase_analytics__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(9500);
var __webpack_async_dependencies__ = __webpack_handle_async_dependencies__([firebase_compat_app__WEBPACK_IMPORTED_MODULE_0__, firebase_compat_auth__WEBPACK_IMPORTED_MODULE_1__, firebase_compat_firestore__WEBPACK_IMPORTED_MODULE_2__, firebase_compat_storage__WEBPACK_IMPORTED_MODULE_3__, firebase_analytics__WEBPACK_IMPORTED_MODULE_4__]);
([firebase_compat_app__WEBPACK_IMPORTED_MODULE_0__, firebase_compat_auth__WEBPACK_IMPORTED_MODULE_1__, firebase_compat_firestore__WEBPACK_IMPORTED_MODULE_2__, firebase_compat_storage__WEBPACK_IMPORTED_MODULE_3__, firebase_analytics__WEBPACK_IMPORTED_MODULE_4__] = __webpack_async_dependencies__.then ? (await __webpack_async_dependencies__)() : __webpack_async_dependencies__);




// Import the functions you need from the SDKs you need

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
    measurementId: "G-H1VGWPNWK6"
};
// Initialize Firebase
if (!firebase_compat_app__WEBPACK_IMPORTED_MODULE_0__["default"].apps.length) {
    firebase_compat_app__WEBPACK_IMPORTED_MODULE_0__["default"].initializeApp(firebaseConfig);
}
const auth = firebase_compat_app__WEBPACK_IMPORTED_MODULE_0__["default"].auth();
const googleAuthProvider = new firebase_compat_app__WEBPACK_IMPORTED_MODULE_0__["default"].auth.GoogleAuthProvider();
const firestore = firebase_compat_app__WEBPACK_IMPORTED_MODULE_0__["default"].firestore();
const storage = firebase_compat_app__WEBPACK_IMPORTED_MODULE_0__["default"].storage();
const STATE_CHANGED = firebase_compat_app__WEBPACK_IMPORTED_MODULE_0__["default"].storage.TaskEvent.STATE_CHANGED;
// export const analytics = getAnalytics(app);
// Helper functions
/*
 * Gets a user/{uid} document with username
 * @param  {string} username
 */ async function getUserWithUsername(username) {
    const usersRef = firestore.collection("users");
    const query = usersRef.where("username", "==", username).limit(1);
    const userDoc = (await query.get()).docs[0];
    return userDoc;
}
/*
 * Converts a firestore document to JSON
 * @param  {DocumentSnapshot} doc
 * /
 */ function postToJSON(doc) {
    const data = doc.data();
    return {
        ...data,
        // Gotcha! firestore timestamp NOT serializable to JSON. Must convert to milliseconds
        createdAt: data.createdAt.toMillis(),
        updatedAt: data.updatedAt.toMillis()
    };
}
const fromMillis = firebase_compat_app__WEBPACK_IMPORTED_MODULE_0__["default"].firestore.Timestamp.fromMillis;
const serverTimestamp = firebase_compat_app__WEBPACK_IMPORTED_MODULE_0__["default"].firestore.FieldValue.serverTimestamp;
const increment = firebase_compat_app__WEBPACK_IMPORTED_MODULE_0__["default"].firestore.FieldValue.increment;

__webpack_async_result__();
} catch(e) { __webpack_async_result__(e); } });

/***/ })

};
;