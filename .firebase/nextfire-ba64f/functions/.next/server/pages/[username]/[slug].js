(() => {
var exports = {};
exports.id = 551;
exports.ids = [551];
exports.modules = {

/***/ 4191:
/***/ ((module) => {

// Exports
module.exports = {
	"container": "Post_container__jmeoa"
};


/***/ }),

/***/ 9724:
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "Z": () => (/* binding */ AuthCheck)
/* harmony export */ });
/* harmony import */ var react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(997);
/* harmony import */ var react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__);
/* harmony import */ var next_link__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(1664);
/* harmony import */ var next_link__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(next_link__WEBPACK_IMPORTED_MODULE_1__);
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(6689);
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_2___default = /*#__PURE__*/__webpack_require__.n(react__WEBPACK_IMPORTED_MODULE_2__);
/* harmony import */ var _lib_context__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(8059);




// Component's children only shown to logged-in users
function AuthCheck(props) {
    const { username  } = (0,react__WEBPACK_IMPORTED_MODULE_2__.useContext)(_lib_context__WEBPACK_IMPORTED_MODULE_3__/* .UserContext */ .S);
    return username ? props.children : props.fallback || /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx((next_link__WEBPACK_IMPORTED_MODULE_1___default()), {
        href: "/enter",
        children: "You must be signed in"
    });
}


/***/ }),

/***/ 686:
/***/ ((module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.a(module, async (__webpack_handle_async_dependencies__, __webpack_async_result__) => { try {
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "Z": () => (/* binding */ Heart)
/* harmony export */ });
/* harmony import */ var react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(997);
/* harmony import */ var react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__);
/* harmony import */ var _lib_firebase__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(2881);
/* harmony import */ var react_firebase_hooks_firestore__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(8829);
/* harmony import */ var react_firebase_hooks_firestore__WEBPACK_IMPORTED_MODULE_2___default = /*#__PURE__*/__webpack_require__.n(react_firebase_hooks_firestore__WEBPACK_IMPORTED_MODULE_2__);
var __webpack_async_dependencies__ = __webpack_handle_async_dependencies__([_lib_firebase__WEBPACK_IMPORTED_MODULE_1__]);
_lib_firebase__WEBPACK_IMPORTED_MODULE_1__ = (__webpack_async_dependencies__.then ? (await __webpack_async_dependencies__)() : __webpack_async_dependencies__)[0];



// Allows user to heart or like a post
function Heart({ postRef  }) {
    // Listen to heart document for currently logged in user
    const heartRef = postRef.collection("hearts").doc(_lib_firebase__WEBPACK_IMPORTED_MODULE_1__/* .auth.currentUser.uid */ .I8.currentUser.uid);
    const [heartDoc] = (0,react_firebase_hooks_firestore__WEBPACK_IMPORTED_MODULE_2__.useDocument)(heartRef);
    // Create a user-to-post relationship
    const addHeart = async ()=>{
        const uid = _lib_firebase__WEBPACK_IMPORTED_MODULE_1__/* .auth.currentUser.uid */ .I8.currentUser.uid;
        const batch = _lib_firebase__WEBPACK_IMPORTED_MODULE_1__/* .firestore.batch */ .RZ.batch();
        batch.update(postRef, {
            heartCount: (0,_lib_firebase__WEBPACK_IMPORTED_MODULE_1__/* .increment */ .nP)(1)
        });
        batch.set(heartRef, {
            uid
        });
        await batch.commit();
    };
    // Remove user-to-post relationship
    const removeHeart = async ()=>{
        const batch = _lib_firebase__WEBPACK_IMPORTED_MODULE_1__/* .firestore.batch */ .RZ.batch();
        batch.update(postRef, {
            heartCount: (0,_lib_firebase__WEBPACK_IMPORTED_MODULE_1__/* .increment */ .nP)(-1)
        });
        batch.delete(heartRef);
        await batch.commit();
    };
    return heartDoc?.exists() ? /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("button", {
        onClick: removeHeart,
        children: "\uD83D\uDC94 Unheart"
    }) : /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("button", {
        onClick: addHeart,
        children: "\uD83D\uDC97 Heart"
    });
}

__webpack_async_result__();
} catch(e) { __webpack_async_result__(e); } });

/***/ }),

/***/ 1031:
/***/ ((module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.a(module, async (__webpack_handle_async_dependencies__, __webpack_async_result__) => { try {
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "Z": () => (/* binding */ PostContent)
/* harmony export */ });
/* harmony import */ var react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(997);
/* harmony import */ var react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__);
/* harmony import */ var next_link__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(1664);
/* harmony import */ var next_link__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(next_link__WEBPACK_IMPORTED_MODULE_1__);
/* harmony import */ var react_markdown__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(3135);
var __webpack_async_dependencies__ = __webpack_handle_async_dependencies__([react_markdown__WEBPACK_IMPORTED_MODULE_2__]);
react_markdown__WEBPACK_IMPORTED_MODULE_2__ = (__webpack_async_dependencies__.then ? (await __webpack_async_dependencies__)() : __webpack_async_dependencies__)[0];



// UI component for main post content
function PostContent({ post  }) {
    const createdAt = typeof post?.createdAt === "number" ? new Date(post.createdAt) : post.createdAt.toDate();
    return /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("div", {
        className: "card",
        children: [
            /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("h1", {
                children: post?.title
            }),
            /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("span", {
                className: "text-sm",
                children: [
                    "Written by",
                    " ",
                    /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)((next_link__WEBPACK_IMPORTED_MODULE_1___default()), {
                        href: `/${post.username}/`,
                        className: "text-info",
                        children: [
                            "@",
                            post.username
                        ]
                    }),
                    " ",
                    "on ",
                    createdAt.toISOString()
                ]
            }),
            /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(react_markdown__WEBPACK_IMPORTED_MODULE_2__["default"], {
                children: post?.content
            })
        ]
    });
}

__webpack_async_result__();
} catch(e) { __webpack_async_result__(e); } });

/***/ }),

/***/ 8059:
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "S": () => (/* binding */ UserContext)
/* harmony export */ });
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(6689);
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(react__WEBPACK_IMPORTED_MODULE_0__);

const UserContext = /*#__PURE__*/ (0,react__WEBPACK_IMPORTED_MODULE_0__.createContext)({
    user: null,
    username: null
});


/***/ }),

/***/ 7991:
/***/ ((module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.a(module, async (__webpack_handle_async_dependencies__, __webpack_async_result__) => { try {
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (/* binding */ Post),
/* harmony export */   "getStaticPaths": () => (/* binding */ getStaticPaths),
/* harmony export */   "getStaticProps": () => (/* binding */ getStaticProps)
/* harmony export */ });
/* harmony import */ var react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(997);
/* harmony import */ var react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__);
/* harmony import */ var _styles_Post_module_css__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(4191);
/* harmony import */ var _styles_Post_module_css__WEBPACK_IMPORTED_MODULE_7___default = /*#__PURE__*/__webpack_require__.n(_styles_Post_module_css__WEBPACK_IMPORTED_MODULE_7__);
/* harmony import */ var _components_PostContent_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(1031);
/* harmony import */ var _lib_firebase__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(2881);
/* harmony import */ var react_firebase_hooks_firestore__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(8829);
/* harmony import */ var react_firebase_hooks_firestore__WEBPACK_IMPORTED_MODULE_3___default = /*#__PURE__*/__webpack_require__.n(react_firebase_hooks_firestore__WEBPACK_IMPORTED_MODULE_3__);
/* harmony import */ var _components_HeartButton__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(686);
/* harmony import */ var _components_AuthCheck__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(9724);
/* harmony import */ var next_link__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(1664);
/* harmony import */ var next_link__WEBPACK_IMPORTED_MODULE_6___default = /*#__PURE__*/__webpack_require__.n(next_link__WEBPACK_IMPORTED_MODULE_6__);
var __webpack_async_dependencies__ = __webpack_handle_async_dependencies__([_components_PostContent_js__WEBPACK_IMPORTED_MODULE_1__, _lib_firebase__WEBPACK_IMPORTED_MODULE_2__, _components_HeartButton__WEBPACK_IMPORTED_MODULE_4__]);
([_components_PostContent_js__WEBPACK_IMPORTED_MODULE_1__, _lib_firebase__WEBPACK_IMPORTED_MODULE_2__, _components_HeartButton__WEBPACK_IMPORTED_MODULE_4__] = __webpack_async_dependencies__.then ? (await __webpack_async_dependencies__)() : __webpack_async_dependencies__);








async function getStaticProps({ params  }) {
    const { username , slug  } = params;
    const userDoc = await (0,_lib_firebase__WEBPACK_IMPORTED_MODULE_2__/* .getUserWithUsername */ .Lp)(username);
    let post;
    let path;
    if (userDoc) {
        const postRef = userDoc.ref.collection("posts").doc(slug);
        post = (0,_lib_firebase__WEBPACK_IMPORTED_MODULE_2__/* .postToJSON */ .WS)(await postRef.get());
        path = postRef.path;
    }
    return {
        props: {
            post,
            path
        },
        revalidate: 5000
    };
}
async function getStaticPaths() {
    // Improve this after using Admin SDK to select empty docs
    const snapshot = await _lib_firebase__WEBPACK_IMPORTED_MODULE_2__/* .firestore.collectionGroup */ .RZ.collectionGroup("posts").get();
    const paths = snapshot.docs.map((doc)=>{
        const { slug , username  } = doc.data();
        return {
            params: {
                username,
                slug
            }
        };
    });
    return {
        paths,
        fallback: "blocking"
    };
}
function Post(props) {
    const postRef = _lib_firebase__WEBPACK_IMPORTED_MODULE_2__/* .firestore.doc */ .RZ.doc(props.path);
    const [realtimePost] = (0,react_firebase_hooks_firestore__WEBPACK_IMPORTED_MODULE_3__.useDocumentData)(postRef);
    // defaults to real-time data, but if data hasn't loaded yet, fallback to pre-rendered data on server from props
    const post = realtimePost || props.post;
    return /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("main", {
        className: (_styles_Post_module_css__WEBPACK_IMPORTED_MODULE_7___default().container),
        children: [
            /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("section", {
                children: /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(_components_PostContent_js__WEBPACK_IMPORTED_MODULE_1__/* ["default"] */ .Z, {
                    post: post
                })
            }),
            /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("aside", {
                className: "card",
                children: [
                    /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("p", {
                        children: /*#__PURE__*/ (0,react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsxs)("strong", {
                            children: [
                                post.heartCount || 0,
                                " \uD83E\uDD0D"
                            ]
                        })
                    }),
                    /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(_components_AuthCheck__WEBPACK_IMPORTED_MODULE_5__/* ["default"] */ .Z, {
                        fallback: /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx((next_link__WEBPACK_IMPORTED_MODULE_6___default()), {
                            href: "/enter",
                            children: /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx("button", {
                                children: "\uD83D\uDC97 Sign Up"
                            })
                        }),
                        children: /*#__PURE__*/ react_jsx_runtime__WEBPACK_IMPORTED_MODULE_0__.jsx(_components_HeartButton__WEBPACK_IMPORTED_MODULE_4__/* ["default"] */ .Z, {
                            postRef: postRef
                        })
                    })
                ]
            })
        ]
    });
}

__webpack_async_result__();
} catch(e) { __webpack_async_result__(e); } });

/***/ }),

/***/ 3280:
/***/ ((module) => {

"use strict";
module.exports = require("next/dist/shared/lib/app-router-context.js");

/***/ }),

/***/ 2796:
/***/ ((module) => {

"use strict";
module.exports = require("next/dist/shared/lib/head-manager-context.js");

/***/ }),

/***/ 4014:
/***/ ((module) => {

"use strict";
module.exports = require("next/dist/shared/lib/i18n/normalize-locale-path.js");

/***/ }),

/***/ 8524:
/***/ ((module) => {

"use strict";
module.exports = require("next/dist/shared/lib/is-plain-object.js");

/***/ }),

/***/ 8020:
/***/ ((module) => {

"use strict";
module.exports = require("next/dist/shared/lib/mitt.js");

/***/ }),

/***/ 4406:
/***/ ((module) => {

"use strict";
module.exports = require("next/dist/shared/lib/page-path/denormalize-page-path.js");

/***/ }),

/***/ 4964:
/***/ ((module) => {

"use strict";
module.exports = require("next/dist/shared/lib/router-context.js");

/***/ }),

/***/ 1751:
/***/ ((module) => {

"use strict";
module.exports = require("next/dist/shared/lib/router/utils/add-path-prefix.js");

/***/ }),

/***/ 6220:
/***/ ((module) => {

"use strict";
module.exports = require("next/dist/shared/lib/router/utils/compare-states.js");

/***/ }),

/***/ 299:
/***/ ((module) => {

"use strict";
module.exports = require("next/dist/shared/lib/router/utils/format-next-pathname-info.js");

/***/ }),

/***/ 3938:
/***/ ((module) => {

"use strict";
module.exports = require("next/dist/shared/lib/router/utils/format-url.js");

/***/ }),

/***/ 9565:
/***/ ((module) => {

"use strict";
module.exports = require("next/dist/shared/lib/router/utils/get-asset-path-from-route.js");

/***/ }),

/***/ 5789:
/***/ ((module) => {

"use strict";
module.exports = require("next/dist/shared/lib/router/utils/get-next-pathname-info.js");

/***/ }),

/***/ 1897:
/***/ ((module) => {

"use strict";
module.exports = require("next/dist/shared/lib/router/utils/is-bot.js");

/***/ }),

/***/ 1428:
/***/ ((module) => {

"use strict";
module.exports = require("next/dist/shared/lib/router/utils/is-dynamic.js");

/***/ }),

/***/ 8854:
/***/ ((module) => {

"use strict";
module.exports = require("next/dist/shared/lib/router/utils/parse-path.js");

/***/ }),

/***/ 1292:
/***/ ((module) => {

"use strict";
module.exports = require("next/dist/shared/lib/router/utils/parse-relative-url.js");

/***/ }),

/***/ 4567:
/***/ ((module) => {

"use strict";
module.exports = require("next/dist/shared/lib/router/utils/path-has-prefix.js");

/***/ }),

/***/ 979:
/***/ ((module) => {

"use strict";
module.exports = require("next/dist/shared/lib/router/utils/querystring.js");

/***/ }),

/***/ 3297:
/***/ ((module) => {

"use strict";
module.exports = require("next/dist/shared/lib/router/utils/remove-trailing-slash.js");

/***/ }),

/***/ 6052:
/***/ ((module) => {

"use strict";
module.exports = require("next/dist/shared/lib/router/utils/resolve-rewrites.js");

/***/ }),

/***/ 4226:
/***/ ((module) => {

"use strict";
module.exports = require("next/dist/shared/lib/router/utils/route-matcher.js");

/***/ }),

/***/ 5052:
/***/ ((module) => {

"use strict";
module.exports = require("next/dist/shared/lib/router/utils/route-regex.js");

/***/ }),

/***/ 9232:
/***/ ((module) => {

"use strict";
module.exports = require("next/dist/shared/lib/utils.js");

/***/ }),

/***/ 6689:
/***/ ((module) => {

"use strict";
module.exports = require("react");

/***/ }),

/***/ 6405:
/***/ ((module) => {

"use strict";
module.exports = require("react-dom");

/***/ }),

/***/ 8829:
/***/ ((module) => {

"use strict";
module.exports = require("react-firebase-hooks/firestore");

/***/ }),

/***/ 997:
/***/ ((module) => {

"use strict";
module.exports = require("react/jsx-runtime");

/***/ }),

/***/ 9500:
/***/ ((module) => {

"use strict";
module.exports = import("firebase/analytics");;

/***/ }),

/***/ 3773:
/***/ ((module) => {

"use strict";
module.exports = import("firebase/compat/app");;

/***/ }),

/***/ 4826:
/***/ ((module) => {

"use strict";
module.exports = import("firebase/compat/auth");;

/***/ }),

/***/ 741:
/***/ ((module) => {

"use strict";
module.exports = import("firebase/compat/firestore");;

/***/ }),

/***/ 451:
/***/ ((module) => {

"use strict";
module.exports = import("firebase/compat/storage");;

/***/ }),

/***/ 3135:
/***/ ((module) => {

"use strict";
module.exports = import("react-markdown");;

/***/ })

};
;

// load runtime
var __webpack_require__ = require("../../webpack-runtime.js");
__webpack_require__.C(exports);
var __webpack_exec__ = (moduleId) => (__webpack_require__(__webpack_require__.s = moduleId))
var __webpack_exports__ = __webpack_require__.X(0, [210,676,664,881], () => (__webpack_exec__(7991)));
module.exports = __webpack_exports__;

})();