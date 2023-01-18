(self.webpackChunk_N_E=self.webpackChunk_N_E||[]).push([[888],{5786:function(e,t,n){"use strict";n.d(t,{$:function(){return tc},A:function(){return c},B:function(){return d},G:function(){return eT},H:function(){return ek},J:function(){return eq},L:function(){return ei},M:function(){return eW},N:function(){return eJ},P:function(){return nE},Q:function(){return eZ},R:function(){return ny},T:function(){return e0},U:function(){return eX},V:function(){return e2},W:function(){return e4},X:function(){return e9},Y:function(){return ta},Z:function(){return to},_:function(){return tl},a:function(){return tJ},a0:function(){return tp},a1:function(){return tm},a2:function(){return tg},a3:function(){return ty},a4:function(){return tv},a5:function(){return tw},a6:function(){return t_},a7:function(){return tb},a8:function(){return tI},a9:function(){return tT},aA:function(){return es},aB:function(){return nX},aC:function(){return nB},aD:function(){return nq},aE:function(){return eb},aI:function(){return t0},aL:function(){return e1},aa:function(){return tS},ab:function(){return tk},ac:function(){return tA},af:function(){return tx},ag:function(){return tR},ah:function(){return tD},ak:function(){return tt},al:function(){return tV},an:function(){return t$},ao:function(){return tK},ap:function(){return T},aq:function(){return em},ar:function(){return ed},as:function(){return g},at:function(){return rs},au:function(){return n2},av:function(){return eg},aw:function(){return y},ax:function(){return b},ay:function(){return nZ},az:function(){return S},b:function(){return tY},c:function(){return nN},d:function(){return nP},e:function(){return nO},f:function(){return nz},g:function(){return nW},h:function(){return nK},i:function(){return ns},j:function(){return nY},k:function(){return ro},l:function(){return n_},m:function(){return rc},o:function(){return u},r:function(){return nb},s:function(){return nw},u:function(){return nT},v:function(){return tq}});var r,i=n(4444),s=n(2238),a=n(3333);function o(e,t){var n={};for(var r in e)Object.prototype.hasOwnProperty.call(e,r)&&0>t.indexOf(r)&&(n[r]=e[r]);if(null!=e&&"function"==typeof Object.getOwnPropertySymbols)for(var i=0,r=Object.getOwnPropertySymbols(e);i<r.length;i++)0>t.indexOf(r[i])&&Object.prototype.propertyIsEnumerable.call(e,r[i])&&(n[r[i]]=e[r[i]]);return n}var l=n(8463);let u={FACEBOOK:"facebook.com",GITHUB:"github.com",GOOGLE:"google.com",PASSWORD:"password",PHONE:"phone",TWITTER:"twitter.com"},c={EMAIL_SIGNIN:"EMAIL_SIGNIN",PASSWORD_RESET:"PASSWORD_RESET",RECOVER_EMAIL:"RECOVER_EMAIL",REVERT_SECOND_FACTOR_ADDITION:"REVERT_SECOND_FACTOR_ADDITION",VERIFY_AND_CHANGE_EMAIL:"VERIFY_AND_CHANGE_EMAIL",VERIFY_EMAIL:"VERIFY_EMAIL"};function h(){return{"dependent-sdk-initialized-before-auth":"Another Firebase SDK was initialized and is trying to use Auth before Auth is initialized. Please be sure to call `initializeAuth` or `getAuth` before starting any other Firebase SDK."}}let d=/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function(){return{"admin-restricted-operation":"This operation is restricted to administrators only.","argument-error":"","app-not-authorized":"This app, identified by the domain where it's hosted, is not authorized to use Firebase Authentication with the provided API key. Review your key configuration in the Google API console.","app-not-installed":"The requested mobile application corresponding to the identifier (Android package name or iOS bundle ID) provided is not installed on this device.","captcha-check-failed":"The reCAPTCHA response token provided is either invalid, expired, already used or the domain associated with it does not match the list of whitelisted domains.","code-expired":"The SMS code has expired. Please re-send the verification code to try again.","cordova-not-ready":"Cordova framework is not ready.","cors-unsupported":"This browser is not supported.","credential-already-in-use":"This credential is already associated with a different user account.","custom-token-mismatch":"The custom token corresponds to a different audience.","requires-recent-login":"This operation is sensitive and requires recent authentication. Log in again before retrying this request.","dependent-sdk-initialized-before-auth":"Another Firebase SDK was initialized and is trying to use Auth before Auth is initialized. Please be sure to call `initializeAuth` or `getAuth` before starting any other Firebase SDK.","dynamic-link-not-activated":"Please activate Dynamic Links in the Firebase Console and agree to the terms and conditions.","email-change-needs-verification":"Multi-factor users must always have a verified email.","email-already-in-use":"The email address is already in use by another account.","emulator-config-failed":'Auth instance has already been used to make a network call. Auth can no longer be configured to use the emulator. Try calling "connectAuthEmulator()" sooner.',"expired-action-code":"The action code has expired.","cancelled-popup-request":"This operation has been cancelled due to another conflicting popup being opened.","internal-error":"An internal AuthError has occurred.","invalid-app-credential":"The phone verification request contains an invalid application verifier. The reCAPTCHA token response is either invalid or expired.","invalid-app-id":"The mobile app identifier is not registed for the current project.","invalid-user-token":"This user's credential isn't valid for this project. This can happen if the user's token has been tampered with, or if the user isn't for the project associated with this API key.","invalid-auth-event":"An internal AuthError has occurred.","invalid-verification-code":"The SMS verification code used to create the phone auth credential is invalid. Please resend the verification code sms and be sure to use the verification code provided by the user.","invalid-continue-uri":"The continue URL provided in the request is invalid.","invalid-cordova-configuration":"The following Cordova plugins must be installed to enable OAuth sign-in: cordova-plugin-buildinfo, cordova-universal-links-plugin, cordova-plugin-browsertab, cordova-plugin-inappbrowser and cordova-plugin-customurlscheme.","invalid-custom-token":"The custom token format is incorrect. Please check the documentation.","invalid-dynamic-link-domain":"The provided dynamic link domain is not configured or authorized for the current project.","invalid-email":"The email address is badly formatted.","invalid-emulator-scheme":"Emulator URL must start with a valid scheme (http:// or https://).","invalid-api-key":"Your API key is invalid, please check you have copied it correctly.","invalid-cert-hash":"The SHA-1 certificate hash provided is invalid.","invalid-credential":"The supplied auth credential is malformed or has expired.","invalid-message-payload":"The email template corresponding to this action contains invalid characters in its message. Please fix by going to the Auth email templates section in the Firebase Console.","invalid-multi-factor-session":"The request does not contain a valid proof of first factor successful sign-in.","invalid-oauth-provider":"EmailAuthProvider is not supported for this operation. This operation only supports OAuth providers.","invalid-oauth-client-id":"The OAuth client ID provided is either invalid or does not match the specified API key.","unauthorized-domain":"This domain is not authorized for OAuth operations for your Firebase project. Edit the list of authorized domains from the Firebase console.","invalid-action-code":"The action code is invalid. This can happen if the code is malformed, expired, or has already been used.","wrong-password":"The password is invalid or the user does not have a password.","invalid-persistence-type":"The specified persistence type is invalid. It can only be local, session or none.","invalid-phone-number":"The format of the phone number provided is incorrect. Please enter the phone number in a format that can be parsed into E.164 format. E.164 phone numbers are written in the format [+][country code][subscriber number including area code].","invalid-provider-id":"The specified provider ID is invalid.","invalid-recipient-email":"The email corresponding to this action failed to send as the provided recipient email address is invalid.","invalid-sender":"The email template corresponding to this action contains an invalid sender email or name. Please fix by going to the Auth email templates section in the Firebase Console.","invalid-verification-id":"The verification ID used to create the phone auth credential is invalid.","invalid-tenant-id":"The Auth instance's tenant ID is invalid.","login-blocked":"Login blocked by user-provided method: {$originalMessage}","missing-android-pkg-name":"An Android Package Name must be provided if the Android App is required to be installed.","auth-domain-config-required":"Be sure to include authDomain when calling firebase.initializeApp(), by following the instructions in the Firebase console.","missing-app-credential":"The phone verification request is missing an application verifier assertion. A reCAPTCHA response token needs to be provided.","missing-verification-code":"The phone auth credential was created with an empty SMS verification code.","missing-continue-uri":"A continue URL must be provided in the request.","missing-iframe-start":"An internal AuthError has occurred.","missing-ios-bundle-id":"An iOS Bundle ID must be provided if an App Store ID is provided.","missing-or-invalid-nonce":"The request does not contain a valid nonce. This can occur if the SHA-256 hash of the provided raw nonce does not match the hashed nonce in the ID token payload.","missing-multi-factor-info":"No second factor identifier is provided.","missing-multi-factor-session":"The request is missing proof of first factor successful sign-in.","missing-phone-number":"To send verification codes, provide a phone number for the recipient.","missing-verification-id":"The phone auth credential was created with an empty verification ID.","app-deleted":"This instance of FirebaseApp has been deleted.","multi-factor-info-not-found":"The user does not have a second factor matching the identifier provided.","multi-factor-auth-required":"Proof of ownership of a second factor is required to complete sign-in.","account-exists-with-different-credential":"An account already exists with the same email address but different sign-in credentials. Sign in using a provider associated with this email address.","network-request-failed":"A network AuthError (such as timeout, interrupted connection or unreachable host) has occurred.","no-auth-event":"An internal AuthError has occurred.","no-such-provider":"User was not linked to an account with the given provider.","null-user":"A null user object was provided as the argument for an operation which requires a non-null user object.","operation-not-allowed":"The given sign-in provider is disabled for this Firebase project. Enable it in the Firebase console, under the sign-in method tab of the Auth section.","operation-not-supported-in-this-environment":'This operation is not supported in the environment this application is running on. "location.protocol" must be http, https or chrome-extension and web storage must be enabled.',"popup-blocked":"Unable to establish a connection with the popup. It may have been blocked by the browser.","popup-closed-by-user":"The popup has been closed by the user before finalizing the operation.","provider-already-linked":"User can only be linked to one identity for the given provider.","quota-exceeded":"The project's quota for this operation has been exceeded.","redirect-cancelled-by-user":"The redirect operation has been cancelled by the user before finalizing.","redirect-operation-pending":"A redirect sign-in operation is already pending.","rejected-credential":"The request contains malformed or mismatching credentials.","second-factor-already-in-use":"The second factor is already enrolled on this account.","maximum-second-factor-count-exceeded":"The maximum allowed number of second factors on a user has been exceeded.","tenant-id-mismatch":"The provided tenant ID does not match the Auth instance's tenant ID",timeout:"The operation has timed out.","user-token-expired":"The user's credential is no longer valid. The user must sign in again.","too-many-requests":"We have blocked all requests from this device due to unusual activity. Try again later.","unauthorized-continue-uri":"The domain of the continue URL is not whitelisted.  Please whitelist the domain in the Firebase console.","unsupported-first-factor":"Enrolling a second factor or signing in with a multi-factor account requires sign-in with a supported first factor.","unsupported-persistence-type":"The current environment does not support the specified persistence type.","unsupported-tenant-operation":"This operation is not supported in a multi-tenant context.","unverified-email":"The operation requires a verified email.","user-cancelled":"The user did not grant your application the permissions it requested.","user-not-found":"There is no user record corresponding to this identifier. The user may have been deleted.","user-disabled":"The user account has been disabled by an administrator.","user-mismatch":"The supplied credentials do not correspond to the previously signed in user.","user-signed-out":"","weak-password":"The password must be 6 characters long or more.","web-storage-unsupported":"This browser is not supported or 3rd party cookies and data may be disabled.","already-initialized":"initializeAuth() has already been called with different options. To avoid this error, call initializeAuth() with the same options as when it was originally called, or call getAuth() to return the already initialized instance."}},f=new i.LL("auth","Firebase",h()),p=new a.Yd("@firebase/auth");function m(e,...t){p.logLevel<=a.in.ERROR&&p.error(`Auth (${s.SDK_VERSION}): ${e}`,...t)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function g(e,...t){throw _(e,...t)}function y(e,...t){return _(e,...t)}function v(e,t,n){let r=Object.assign(Object.assign({},h()),{[t]:n}),s=new i.LL("auth","Firebase",r);return s.create(t,{appName:e.name})}function w(e,t,n){if(!(t instanceof n))throw n.name!==t.constructor.name&&g(e,"argument-error"),v(e,"argument-error",`Type of ${t.constructor.name} does not match expected instance.Did you pass a reference from a different Auth SDK?`)}function _(e,...t){if("string"!=typeof e){let n=t[0],r=[...t.slice(1)];return r[0]&&(r[0].appName=e.name),e._errorFactory.create(n,...r)}return f.create(e,...t)}function b(e,t,...n){if(!e)throw _(t,...n)}function I(e){let t="INTERNAL ASSERTION FAILED: "+e;throw m(t),Error(t)}function T(e,t){e||I(t)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let E=new Map;function S(e){T(e instanceof Function,"Expected a class definition");let t=E.get(e);return t?(T(t instanceof e,"Instance stored in cache mismatched with class"),t):(t=new e,E.set(e,t),t)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function k(){var e;return"undefined"!=typeof self&&(null===(e=self.location)||void 0===e?void 0:e.href)||""}function A(){return"http:"===C()||"https:"===C()}function C(){var e;return"undefined"!=typeof self&&(null===(e=self.location)||void 0===e?void 0:e.protocol)||null}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class x{constructor(e,t){this.shortDelay=e,this.longDelay=t,T(t>e,"Short delay should be less than long delay!"),this.isMobile=(0,i.uI)()||(0,i.b$)()}get(){return!("undefined"!=typeof navigator&&navigator&&"onLine"in navigator&&"boolean"==typeof navigator.onLine&&(A()||(0,i.ru)()||"connection"in navigator))||navigator.onLine?this.isMobile?this.longDelay:this.shortDelay:Math.min(5e3,this.shortDelay)}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function R(e,t){T(e.emulator,"Emulator should always be set here");let{url:n}=e.emulator;return t?`${n}${t.startsWith("/")?t.slice(1):t}`:n}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class D{static initialize(e,t,n){this.fetchImpl=e,t&&(this.headersImpl=t),n&&(this.responseImpl=n)}static fetch(){return this.fetchImpl?this.fetchImpl:"undefined"!=typeof self&&"fetch"in self?self.fetch:void I("Could not find fetch implementation, make sure you call FetchProvider.initialize() with an appropriate polyfill")}static headers(){return this.headersImpl?this.headersImpl:"undefined"!=typeof self&&"Headers"in self?self.Headers:void I("Could not find Headers implementation, make sure you call FetchProvider.initialize() with an appropriate polyfill")}static response(){return this.responseImpl?this.responseImpl:"undefined"!=typeof self&&"Response"in self?self.Response:void I("Could not find Response implementation, make sure you call FetchProvider.initialize() with an appropriate polyfill")}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let N={CREDENTIAL_MISMATCH:"custom-token-mismatch",MISSING_CUSTOM_TOKEN:"internal-error",INVALID_IDENTIFIER:"invalid-email",MISSING_CONTINUE_URI:"internal-error",INVALID_PASSWORD:"wrong-password",MISSING_PASSWORD:"internal-error",EMAIL_EXISTS:"email-already-in-use",PASSWORD_LOGIN_DISABLED:"operation-not-allowed",INVALID_IDP_RESPONSE:"invalid-credential",INVALID_PENDING_TOKEN:"invalid-credential",FEDERATED_USER_ID_ALREADY_LINKED:"credential-already-in-use",MISSING_REQ_TYPE:"internal-error",EMAIL_NOT_FOUND:"user-not-found",RESET_PASSWORD_EXCEED_LIMIT:"too-many-requests",EXPIRED_OOB_CODE:"expired-action-code",INVALID_OOB_CODE:"invalid-action-code",MISSING_OOB_CODE:"internal-error",CREDENTIAL_TOO_OLD_LOGIN_AGAIN:"requires-recent-login",INVALID_ID_TOKEN:"invalid-user-token",TOKEN_EXPIRED:"user-token-expired",USER_NOT_FOUND:"user-token-expired",TOO_MANY_ATTEMPTS_TRY_LATER:"too-many-requests",INVALID_CODE:"invalid-verification-code",INVALID_SESSION_INFO:"invalid-verification-id",INVALID_TEMPORARY_PROOF:"invalid-credential",MISSING_SESSION_INFO:"missing-verification-id",SESSION_EXPIRED:"code-expired",MISSING_ANDROID_PACKAGE_NAME:"missing-android-pkg-name",UNAUTHORIZED_DOMAIN:"unauthorized-continue-uri",INVALID_OAUTH_CLIENT_ID:"invalid-oauth-client-id",ADMIN_ONLY_OPERATION:"admin-restricted-operation",INVALID_MFA_PENDING_CREDENTIAL:"invalid-multi-factor-session",MFA_ENROLLMENT_NOT_FOUND:"multi-factor-info-not-found",MISSING_MFA_ENROLLMENT_ID:"missing-multi-factor-info",MISSING_MFA_PENDING_CREDENTIAL:"missing-multi-factor-session",SECOND_FACTOR_EXISTS:"second-factor-already-in-use",SECOND_FACTOR_LIMIT_EXCEEDED:"maximum-second-factor-count-exceeded",BLOCKING_FUNCTION_ERROR_RESPONSE:"internal-error"},O=new x(3e4,6e4);function P(e,t){return e.tenantId&&!t.tenantId?Object.assign(Object.assign({},t),{tenantId:e.tenantId}):t}async function L(e,t,n,r,s={}){return M(e,s,async()=>{let s={},a={};r&&("GET"===t?a=r:s={body:JSON.stringify(r)});let o=(0,i.xO)(Object.assign({key:e.config.apiKey},a)).slice(1),l=await e._getAdditionalHeaders();return l["Content-Type"]="application/json",e.languageCode&&(l["X-Firebase-Locale"]=e.languageCode),D.fetch()(U(e,e.config.apiHost,n,o),Object.assign({method:t,headers:l,referrerPolicy:"no-referrer"},s))})}async function M(e,t,n){e._canInitEmulator=!1;let r=Object.assign(Object.assign({},N),t);try{let s=new V(e),a=await Promise.race([n(),s.promise]);s.clearNetworkTimeout();let o=await a.json();if("needConfirmation"in o)throw q(e,"account-exists-with-different-credential",o);if(a.ok&&!("errorMessage"in o))return o;{let l=a.ok?o.errorMessage:o.error.message,[u,c]=l.split(" : ");if("FEDERATED_USER_ID_ALREADY_LINKED"===u)throw q(e,"credential-already-in-use",o);if("EMAIL_EXISTS"===u)throw q(e,"email-already-in-use",o);if("USER_DISABLED"===u)throw q(e,"user-disabled",o);let h=r[u]||u.toLowerCase().replace(/[_\s]+/g,"-");if(c)throw v(e,h,c);g(e,h)}}catch(d){if(d instanceof i.ZR)throw d;g(e,"network-request-failed")}}async function F(e,t,n,r,i={}){let s=await L(e,t,n,r,i);return"mfaPendingCredential"in s&&g(e,"multi-factor-auth-required",{_serverResponse:s}),s}function U(e,t,n,r){let i=`${t}${n}?${r}`;return e.config.emulator?R(e.config,i):`${e.config.apiScheme}://${i}`}class V{constructor(e){this.auth=e,this.timer=null,this.promise=new Promise((e,t)=>{this.timer=setTimeout(()=>t(y(this.auth,"network-request-failed")),O.get())})}clearNetworkTimeout(){clearTimeout(this.timer)}}function q(e,t,n){let r={appName:e.name};n.email&&(r.email=n.email),n.phoneNumber&&(r.phoneNumber=n.phoneNumber);let i=y(e,t,r);return i.customData._tokenResponse=n,i}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function B(e,t){return L(e,"POST","/v1/accounts:delete",t)}async function j(e,t){return L(e,"POST","/v1/accounts:update",t)}async function $(e,t){return L(e,"POST","/v1/accounts:lookup",t)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function z(e){if(e)try{let t=new Date(Number(e));if(!isNaN(t.getTime()))return t.toUTCString()}catch(n){}}async function G(e,t=!1){let n=(0,i.m9)(e),r=await n.getIdToken(t),s=H(r);b(s&&s.exp&&s.auth_time&&s.iat,n.auth,"internal-error");let a="object"==typeof s.firebase?s.firebase:void 0,o=null==a?void 0:a.sign_in_provider;return{claims:s,token:r,authTime:z(K(s.auth_time)),issuedAtTime:z(K(s.iat)),expirationTime:z(K(s.exp)),signInProvider:o||null,signInSecondFactor:(null==a?void 0:a.sign_in_second_factor)||null}}function K(e){return 1e3*Number(e)}function H(e){let[t,n,r]=e.split(".");if(void 0===t||void 0===n||void 0===r)return m("JWT malformed, contained fewer than 3 sections"),null;try{let s=(0,i.tV)(n);if(!s)return m("Failed to decode base64 JWT payload"),null;return JSON.parse(s)}catch(a){return m("Caught error parsing JWT payload as JSON",null==a?void 0:a.toString()),null}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function W(e,t,n=!1){if(n)return t;try{return await t}catch(r){throw r instanceof i.ZR&&function({code:e}){return"auth/user-disabled"===e||"auth/user-token-expired"===e}(r)&&e.auth.currentUser===e&&await e.auth.signOut(),r}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class Q{constructor(e){this.user=e,this.isRunning=!1,this.timerId=null,this.errorBackoff=3e4}_start(){this.isRunning||(this.isRunning=!0,this.schedule())}_stop(){this.isRunning&&(this.isRunning=!1,null!==this.timerId&&clearTimeout(this.timerId))}getInterval(e){var t;if(e){let n=this.errorBackoff;return this.errorBackoff=Math.min(2*this.errorBackoff,96e4),n}{this.errorBackoff=3e4;let r=null!==(t=this.user.stsTokenManager.expirationTime)&&void 0!==t?t:0,i=r-Date.now()-3e5;return Math.max(0,i)}}schedule(e=!1){if(!this.isRunning)return;let t=this.getInterval(e);this.timerId=setTimeout(async()=>{await this.iteration()},t)}async iteration(){try{await this.user.getIdToken(!0)}catch(e){(null==e?void 0:e.code)==="auth/network-request-failed"&&this.schedule(!0);return}this.schedule()}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class Y{constructor(e,t){this.createdAt=e,this.lastLoginAt=t,this._initializeTime()}_initializeTime(){this.lastSignInTime=z(this.lastLoginAt),this.creationTime=z(this.createdAt)}_copy(e){this.createdAt=e.createdAt,this.lastLoginAt=e.lastLoginAt,this._initializeTime()}toJSON(){return{createdAt:this.createdAt,lastLoginAt:this.lastLoginAt}}}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function X(e){var t;let n=e.auth,r=await e.getIdToken(),i=await W(e,$(n,{idToken:r}));b(null==i?void 0:i.users.length,n,"internal-error");let s=i.users[0];e._notifyReloadListener(s);let a=(null===(t=s.providerUserInfo)||void 0===t?void 0:t.length)?s.providerUserInfo.map(e=>{var{providerId:t}=e,n=o(e,["providerId"]);return{providerId:t,uid:n.rawId||"",displayName:n.displayName||null,email:n.email||null,phoneNumber:n.phoneNumber||null,photoURL:n.photoUrl||null}}):[],l=function(e,t){let n=e.filter(e=>!t.some(t=>t.providerId===e.providerId));return[...n,...t]}(e.providerData,a),u=e.isAnonymous,c=!(e.email&&s.passwordHash)&&!(null==l?void 0:l.length),h={uid:s.localId,displayName:s.displayName||null,photoURL:s.photoUrl||null,email:s.email||null,emailVerified:s.emailVerified||!1,phoneNumber:s.phoneNumber||null,tenantId:s.tenantId||null,providerData:l,metadata:new Y(s.createdAt,s.lastLoginAt),isAnonymous:!!u&&c};Object.assign(e,h)}async function J(e){let t=(0,i.m9)(e);await X(t),await t.auth._persistUserIfCurrent(t),t.auth._notifyListenersIfCurrent(t)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function Z(e,t){let n=await M(e,{},async()=>{let n=(0,i.xO)({grant_type:"refresh_token",refresh_token:t}).slice(1),{tokenApiHost:r,apiKey:s}=e.config,a=U(e,r,"/v1/token",`key=${s}`),o=await e._getAdditionalHeaders();return o["Content-Type"]="application/x-www-form-urlencoded",D.fetch()(a,{method:"POST",headers:o,body:n})});return{accessToken:n.access_token,expiresIn:n.expires_in,refreshToken:n.refresh_token}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class ee{constructor(){this.refreshToken=null,this.accessToken=null,this.expirationTime=null}get isExpired(){return!this.expirationTime||Date.now()>this.expirationTime-3e4}updateFromServerResponse(e){b(e.idToken,"internal-error"),b(void 0!==e.idToken,"internal-error"),b(void 0!==e.refreshToken,"internal-error");let t="expiresIn"in e&&void 0!==e.expiresIn?Number(e.expiresIn):function(e){let t=H(e);return b(t,"internal-error"),b(void 0!==t.exp,"internal-error"),b(void 0!==t.iat,"internal-error"),Number(t.exp)-Number(t.iat)}(e.idToken);this.updateTokensAndExpiration(e.idToken,e.refreshToken,t)}async getToken(e,t=!1){return(b(!this.accessToken||this.refreshToken,e,"user-token-expired"),t||!this.accessToken||this.isExpired)?this.refreshToken?(await this.refresh(e,this.refreshToken),this.accessToken):null:this.accessToken}clearRefreshToken(){this.refreshToken=null}async refresh(e,t){let{accessToken:n,refreshToken:r,expiresIn:i}=await Z(e,t);this.updateTokensAndExpiration(n,r,Number(i))}updateTokensAndExpiration(e,t,n){this.refreshToken=t||null,this.accessToken=e||null,this.expirationTime=Date.now()+1e3*n}static fromJSON(e,t){let{refreshToken:n,accessToken:r,expirationTime:i}=t,s=new ee;return n&&(b("string"==typeof n,"internal-error",{appName:e}),s.refreshToken=n),r&&(b("string"==typeof r,"internal-error",{appName:e}),s.accessToken=r),i&&(b("number"==typeof i,"internal-error",{appName:e}),s.expirationTime=i),s}toJSON(){return{refreshToken:this.refreshToken,accessToken:this.accessToken,expirationTime:this.expirationTime}}_assign(e){this.accessToken=e.accessToken,this.refreshToken=e.refreshToken,this.expirationTime=e.expirationTime}_clone(){return Object.assign(new ee,this.toJSON())}_performRefresh(){return I("not implemented")}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function et(e,t){b("string"==typeof e||void 0===e,"internal-error",{appName:t})}class en{constructor(e){var{uid:t,auth:n,stsTokenManager:r}=e,i=o(e,["uid","auth","stsTokenManager"]);this.providerId="firebase",this.proactiveRefresh=new Q(this),this.reloadUserInfo=null,this.reloadListener=null,this.uid=t,this.auth=n,this.stsTokenManager=r,this.accessToken=r.accessToken,this.displayName=i.displayName||null,this.email=i.email||null,this.emailVerified=i.emailVerified||!1,this.phoneNumber=i.phoneNumber||null,this.photoURL=i.photoURL||null,this.isAnonymous=i.isAnonymous||!1,this.tenantId=i.tenantId||null,this.providerData=i.providerData?[...i.providerData]:[],this.metadata=new Y(i.createdAt||void 0,i.lastLoginAt||void 0)}async getIdToken(e){let t=await W(this,this.stsTokenManager.getToken(this.auth,e));return b(t,this.auth,"internal-error"),this.accessToken!==t&&(this.accessToken=t,await this.auth._persistUserIfCurrent(this),this.auth._notifyListenersIfCurrent(this)),t}getIdTokenResult(e){return G(this,e)}reload(){return J(this)}_assign(e){this!==e&&(b(this.uid===e.uid,this.auth,"internal-error"),this.displayName=e.displayName,this.photoURL=e.photoURL,this.email=e.email,this.emailVerified=e.emailVerified,this.phoneNumber=e.phoneNumber,this.isAnonymous=e.isAnonymous,this.tenantId=e.tenantId,this.providerData=e.providerData.map(e=>Object.assign({},e)),this.metadata._copy(e.metadata),this.stsTokenManager._assign(e.stsTokenManager))}_clone(e){return new en(Object.assign(Object.assign({},this),{auth:e,stsTokenManager:this.stsTokenManager._clone()}))}_onReload(e){b(!this.reloadListener,this.auth,"internal-error"),this.reloadListener=e,this.reloadUserInfo&&(this._notifyReloadListener(this.reloadUserInfo),this.reloadUserInfo=null)}_notifyReloadListener(e){this.reloadListener?this.reloadListener(e):this.reloadUserInfo=e}_startProactiveRefresh(){this.proactiveRefresh._start()}_stopProactiveRefresh(){this.proactiveRefresh._stop()}async _updateTokensIfNecessary(e,t=!1){let n=!1;e.idToken&&e.idToken!==this.stsTokenManager.accessToken&&(this.stsTokenManager.updateFromServerResponse(e),n=!0),t&&await X(this),await this.auth._persistUserIfCurrent(this),n&&this.auth._notifyListenersIfCurrent(this)}async delete(){let e=await this.getIdToken();return await W(this,B(this.auth,{idToken:e})),this.stsTokenManager.clearRefreshToken(),this.auth.signOut()}toJSON(){return Object.assign(Object.assign({uid:this.uid,email:this.email||void 0,emailVerified:this.emailVerified,displayName:this.displayName||void 0,isAnonymous:this.isAnonymous,photoURL:this.photoURL||void 0,phoneNumber:this.phoneNumber||void 0,tenantId:this.tenantId||void 0,providerData:this.providerData.map(e=>Object.assign({},e)),stsTokenManager:this.stsTokenManager.toJSON(),_redirectEventId:this._redirectEventId},this.metadata.toJSON()),{apiKey:this.auth.config.apiKey,appName:this.auth.name})}get refreshToken(){return this.stsTokenManager.refreshToken||""}static _fromJSON(e,t){var n,r,i,s,a,o,l,u;let c=null!==(n=t.displayName)&&void 0!==n?n:void 0,h=null!==(r=t.email)&&void 0!==r?r:void 0,d=null!==(i=t.phoneNumber)&&void 0!==i?i:void 0,f=null!==(s=t.photoURL)&&void 0!==s?s:void 0,p=null!==(a=t.tenantId)&&void 0!==a?a:void 0,m=null!==(o=t._redirectEventId)&&void 0!==o?o:void 0,g=null!==(l=t.createdAt)&&void 0!==l?l:void 0,y=null!==(u=t.lastLoginAt)&&void 0!==u?u:void 0,{uid:v,emailVerified:w,isAnonymous:_,providerData:I,stsTokenManager:T}=t;b(v&&T,e,"internal-error");let E=ee.fromJSON(this.name,T);b("string"==typeof v,e,"internal-error"),et(c,e.name),et(h,e.name),b("boolean"==typeof w,e,"internal-error"),b("boolean"==typeof _,e,"internal-error"),et(d,e.name),et(f,e.name),et(p,e.name),et(m,e.name),et(g,e.name),et(y,e.name);let S=new en({uid:v,auth:e,email:h,emailVerified:w,displayName:c,isAnonymous:_,photoURL:f,phoneNumber:d,tenantId:p,stsTokenManager:E,createdAt:g,lastLoginAt:y});return I&&Array.isArray(I)&&(S.providerData=I.map(e=>Object.assign({},e))),m&&(S._redirectEventId=m),S}static async _fromIdTokenResponse(e,t,n=!1){let r=new ee;r.updateFromServerResponse(t);let i=new en({uid:t.localId,auth:e,stsTokenManager:r,isAnonymous:n});return await X(i),i}}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class er{constructor(){this.type="NONE",this.storage={}}async _isAvailable(){return!0}async _set(e,t){this.storage[e]=t}async _get(e){let t=this.storage[e];return void 0===t?null:t}async _remove(e){delete this.storage[e]}_addListener(e,t){}_removeListener(e,t){}}er.type="NONE";let ei=er;/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function es(e,t,n){return`firebase:${e}:${t}:${n}`}class ea{constructor(e,t,n){this.persistence=e,this.auth=t,this.userKey=n;let{config:r,name:i}=this.auth;this.fullUserKey=es(this.userKey,r.apiKey,i),this.fullPersistenceKey=es("persistence",r.apiKey,i),this.boundEventHandler=t._onStorageEvent.bind(t),this.persistence._addListener(this.fullUserKey,this.boundEventHandler)}setCurrentUser(e){return this.persistence._set(this.fullUserKey,e.toJSON())}async getCurrentUser(){let e=await this.persistence._get(this.fullUserKey);return e?en._fromJSON(this.auth,e):null}removeCurrentUser(){return this.persistence._remove(this.fullUserKey)}savePersistenceForRedirect(){return this.persistence._set(this.fullPersistenceKey,this.persistence.type)}async setPersistence(e){if(this.persistence===e)return;let t=await this.getCurrentUser();if(await this.removeCurrentUser(),this.persistence=e,t)return this.setCurrentUser(t)}delete(){this.persistence._removeListener(this.fullUserKey,this.boundEventHandler)}static async create(e,t,n="authUser"){if(!t.length)return new ea(S(ei),e,n);let r=(await Promise.all(t.map(async e=>{if(await e._isAvailable())return e}))).filter(e=>e),i=r[0]||S(ei),s=es(n,e.config.apiKey,e.name),a=null;for(let o of t)try{let l=await o._get(s);if(l){let u=en._fromJSON(e,l);o!==i&&(a=u),i=o;break}}catch(c){}let h=r.filter(e=>e._shouldAllowMigration);return i._shouldAllowMigration&&h.length&&(i=h[0],a&&await i._set(s,a.toJSON()),await Promise.all(t.map(async e=>{if(e!==i)try{await e._remove(s)}catch(t){}}))),new ea(i,e,n)}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function eo(e){let t=e.toLowerCase();if(t.includes("opera/")||t.includes("opr/")||t.includes("opios/"))return"Opera";if(eh(t))return"IEMobile";if(t.includes("msie")||t.includes("trident/"))return"IE";{if(t.includes("edge/"))return"Edge";if(el(t))return"Firefox";if(t.includes("silk/"))return"Silk";if(ef(t))return"Blackberry";if(ep(t))return"Webos";if(eu(t))return"Safari";if((t.includes("chrome/")||ec(t))&&!t.includes("edge/"))return"Chrome";if(ed(t))return"Android";let n=e.match(/([a-zA-Z\d\.]+)\/[a-zA-Z\d\.]*$/);if((null==n?void 0:n.length)===2)return n[1]}return"Other"}function el(e=(0,i.z$)()){return/firefox\//i.test(e)}function eu(e=(0,i.z$)()){let t=e.toLowerCase();return t.includes("safari/")&&!t.includes("chrome/")&&!t.includes("crios/")&&!t.includes("android")}function ec(e=(0,i.z$)()){return/crios\//i.test(e)}function eh(e=(0,i.z$)()){return/iemobile/i.test(e)}function ed(e=(0,i.z$)()){return/android/i.test(e)}function ef(e=(0,i.z$)()){return/blackberry/i.test(e)}function ep(e=(0,i.z$)()){return/webos/i.test(e)}function em(e=(0,i.z$)()){return/iphone|ipad|ipod/i.test(e)||/macintosh/i.test(e)&&/mobile/i.test(e)}function eg(e=(0,i.z$)()){return/(iPad|iPhone|iPod).*OS 7_\d/i.test(e)||/(iPad|iPhone|iPod).*OS 8_\d/i.test(e)}function ey(e=(0,i.z$)()){return em(e)||ed(e)||ep(e)||ef(e)||/windows phone/i.test(e)||eh(e)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function ev(e,t=[]){let n;switch(e){case"Browser":n=eo((0,i.z$)());break;case"Worker":n=`${eo((0,i.z$)())}-${e}`;break;default:n=e}let r=t.length?t.join(","):"FirebaseCore-web";return`${n}/JsCore/${s.SDK_VERSION}/${r}`}/**
 * @license
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class ew{constructor(e){this.auth=e,this.queue=[]}pushCallback(e,t){let n=t=>new Promise((n,r)=>{try{let i=e(t);n(i)}catch(s){r(s)}});n.onAbort=t,this.queue.push(n);let r=this.queue.length-1;return()=>{this.queue[r]=()=>Promise.resolve()}}async runMiddleware(e){if(this.auth.currentUser===e)return;let t=[];try{for(let n of this.queue)await n(e),n.onAbort&&t.push(n.onAbort)}catch(s){for(let r of(t.reverse(),t))try{r()}catch(i){}throw this.auth._errorFactory.create("login-blocked",{originalMessage:null==s?void 0:s.message})}}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class e_{constructor(e,t,n){this.app=e,this.heartbeatServiceProvider=t,this.config=n,this.currentUser=null,this.emulatorConfig=null,this.operations=Promise.resolve(),this.authStateSubscription=new eI(this),this.idTokenSubscription=new eI(this),this.beforeStateQueue=new ew(this),this.redirectUser=null,this.isProactiveRefreshEnabled=!1,this._canInitEmulator=!0,this._isInitialized=!1,this._deleted=!1,this._initializationPromise=null,this._popupRedirectResolver=null,this._errorFactory=f,this.lastNotifiedUid=void 0,this.languageCode=null,this.tenantId=null,this.settings={appVerificationDisabledForTesting:!1},this.frameworks=[],this.name=e.name,this.clientVersion=n.sdkClientVersion}_initializeWithPersistence(e,t){return t&&(this._popupRedirectResolver=S(t)),this._initializationPromise=this.queue(async()=>{var n,r;if(!this._deleted&&(this.persistenceManager=await ea.create(this,e),!this._deleted)){if(null===(n=this._popupRedirectResolver)||void 0===n?void 0:n._shouldInitProactively)try{await this._popupRedirectResolver._initialize(this)}catch(i){}await this.initializeCurrentUser(t),this.lastNotifiedUid=(null===(r=this.currentUser)||void 0===r?void 0:r.uid)||null,this._deleted||(this._isInitialized=!0)}}),this._initializationPromise}async _onStorageEvent(){if(this._deleted)return;let e=await this.assertedPersistence.getCurrentUser();if(this.currentUser||e){if(this.currentUser&&e&&this.currentUser.uid===e.uid){this._currentUser._assign(e),await this.currentUser.getIdToken();return}await this._updateCurrentUser(e,!0)}}async initializeCurrentUser(e){var t;let n=await this.assertedPersistence.getCurrentUser(),r=n,i=!1;if(e&&this.config.authDomain){await this.getOrInitRedirectPersistenceManager();let s=null===(t=this.redirectUser)||void 0===t?void 0:t._redirectEventId,a=null==r?void 0:r._redirectEventId,o=await this.tryRedirectSignIn(e);(!s||s===a)&&(null==o?void 0:o.user)&&(r=o.user,i=!0)}if(!r)return this.directlySetCurrentUser(null);if(!r._redirectEventId){if(i)try{await this.beforeStateQueue.runMiddleware(r)}catch(l){r=n,this._popupRedirectResolver._overrideRedirectResult(this,()=>Promise.reject(l))}return r?this.reloadAndSetCurrentUserOrClear(r):this.directlySetCurrentUser(null)}return(b(this._popupRedirectResolver,this,"argument-error"),await this.getOrInitRedirectPersistenceManager(),this.redirectUser&&this.redirectUser._redirectEventId===r._redirectEventId)?this.directlySetCurrentUser(r):this.reloadAndSetCurrentUserOrClear(r)}async tryRedirectSignIn(e){let t=null;try{t=await this._popupRedirectResolver._completeRedirectFn(this,e,!0)}catch(n){await this._setRedirectUser(null)}return t}async reloadAndSetCurrentUserOrClear(e){try{await X(e)}catch(t){if((null==t?void 0:t.code)!=="auth/network-request-failed")return this.directlySetCurrentUser(null)}return this.directlySetCurrentUser(e)}useDeviceLanguage(){this.languageCode=function(){if("undefined"==typeof navigator)return null;let e=navigator;return e.languages&&e.languages[0]||e.language||null}()}async _delete(){this._deleted=!0}async updateCurrentUser(e){let t=e?(0,i.m9)(e):null;return t&&b(t.auth.config.apiKey===this.config.apiKey,this,"invalid-user-token"),this._updateCurrentUser(t&&t._clone(this))}async _updateCurrentUser(e,t=!1){if(!this._deleted)return e&&b(this.tenantId===e.tenantId,this,"tenant-id-mismatch"),t||await this.beforeStateQueue.runMiddleware(e),this.queue(async()=>{await this.directlySetCurrentUser(e),this.notifyAuthListeners()})}async signOut(){return await this.beforeStateQueue.runMiddleware(null),(this.redirectPersistenceManager||this._popupRedirectResolver)&&await this._setRedirectUser(null),this._updateCurrentUser(null,!0)}setPersistence(e){return this.queue(async()=>{await this.assertedPersistence.setPersistence(S(e))})}_getPersistence(){return this.assertedPersistence.persistence.type}_updateErrorMap(e){this._errorFactory=new i.LL("auth","Firebase",e())}onAuthStateChanged(e,t,n){return this.registerStateListener(this.authStateSubscription,e,t,n)}beforeAuthStateChanged(e,t){return this.beforeStateQueue.pushCallback(e,t)}onIdTokenChanged(e,t,n){return this.registerStateListener(this.idTokenSubscription,e,t,n)}toJSON(){var e;return{apiKey:this.config.apiKey,authDomain:this.config.authDomain,appName:this.name,currentUser:null===(e=this._currentUser)||void 0===e?void 0:e.toJSON()}}async _setRedirectUser(e,t){let n=await this.getOrInitRedirectPersistenceManager(t);return null===e?n.removeCurrentUser():n.setCurrentUser(e)}async getOrInitRedirectPersistenceManager(e){if(!this.redirectPersistenceManager){let t=e&&S(e)||this._popupRedirectResolver;b(t,this,"argument-error"),this.redirectPersistenceManager=await ea.create(this,[S(t._redirectPersistence)],"redirectUser"),this.redirectUser=await this.redirectPersistenceManager.getCurrentUser()}return this.redirectPersistenceManager}async _redirectUserForId(e){var t,n;return(this._isInitialized&&await this.queue(async()=>{}),(null===(t=this._currentUser)||void 0===t?void 0:t._redirectEventId)===e)?this._currentUser:(null===(n=this.redirectUser)||void 0===n?void 0:n._redirectEventId)===e?this.redirectUser:null}async _persistUserIfCurrent(e){if(e===this.currentUser)return this.queue(async()=>this.directlySetCurrentUser(e))}_notifyListenersIfCurrent(e){e===this.currentUser&&this.notifyAuthListeners()}_key(){return`${this.config.authDomain}:${this.config.apiKey}:${this.name}`}_startProactiveRefresh(){this.isProactiveRefreshEnabled=!0,this.currentUser&&this._currentUser._startProactiveRefresh()}_stopProactiveRefresh(){this.isProactiveRefreshEnabled=!1,this.currentUser&&this._currentUser._stopProactiveRefresh()}get _currentUser(){return this.currentUser}notifyAuthListeners(){var e,t;if(!this._isInitialized)return;this.idTokenSubscription.next(this.currentUser);let n=null!==(t=null===(e=this.currentUser)||void 0===e?void 0:e.uid)&&void 0!==t?t:null;this.lastNotifiedUid!==n&&(this.lastNotifiedUid=n,this.authStateSubscription.next(this.currentUser))}registerStateListener(e,t,n,r){if(this._deleted)return()=>{};let i="function"==typeof t?t:t.next.bind(t),s=this._isInitialized?Promise.resolve():this._initializationPromise;return(b(s,this,"internal-error"),s.then(()=>i(this.currentUser)),"function"==typeof t)?e.addObserver(t,n,r):e.addObserver(t)}async directlySetCurrentUser(e){this.currentUser&&this.currentUser!==e&&this._currentUser._stopProactiveRefresh(),e&&this.isProactiveRefreshEnabled&&e._startProactiveRefresh(),this.currentUser=e,e?await this.assertedPersistence.setCurrentUser(e):await this.assertedPersistence.removeCurrentUser()}queue(e){return this.operations=this.operations.then(e,e),this.operations}get assertedPersistence(){return b(this.persistenceManager,this,"internal-error"),this.persistenceManager}_logFramework(e){!e||this.frameworks.includes(e)||(this.frameworks.push(e),this.frameworks.sort(),this.clientVersion=ev(this.config.clientPlatform,this._getFrameworks()))}_getFrameworks(){return this.frameworks}async _getAdditionalHeaders(){var e;let t={"X-Client-Version":this.clientVersion};this.app.options.appId&&(t["X-Firebase-gmpid"]=this.app.options.appId);let n=await (null===(e=this.heartbeatServiceProvider.getImmediate({optional:!0}))||void 0===e?void 0:e.getHeartbeatsHeader());return n&&(t["X-Firebase-Client"]=n),t}}function eb(e){return(0,i.m9)(e)}class eI{constructor(e){this.auth=e,this.observer=null,this.addObserver=(0,i.ne)(e=>this.observer=e)}get next(){return b(this.observer,this.auth,"internal-error"),this.observer.next.bind(this.observer)}}function eT(e,t,n){let r=eb(e);b(r._canInitEmulator,r,"emulator-config-failed"),b(/^https?:\/\//.test(t),r,"invalid-emulator-scheme");let i=!!(null==n?void 0:n.disableWarnings),s=eE(t),{host:a,port:o}=function(e){let t=eE(e),n=/(\/\/)?([^?#/]+)/.exec(e.substr(t.length));if(!n)return{host:"",port:null};let r=n[2].split("@").pop()||"",i=/^(\[[^\]]+\])(:|$)/.exec(r);if(i){let s=i[1];return{host:s,port:eS(r.substr(s.length+1))}}{let[a,o]=r.split(":");return{host:a,port:eS(o)}}}(t),l=null===o?"":`:${o}`;r.config.emulator={url:`${s}//${a}${l}/`},r.settings.appVerificationDisabledForTesting=!0,r.emulatorConfig=Object.freeze({host:a,port:o,protocol:s.replace(":",""),options:Object.freeze({disableWarnings:i})}),i||function(){function e(){let e=document.createElement("p"),t=e.style;e.innerText="Running in emulator mode. Do not use with production credentials.",t.position="fixed",t.width="100%",t.backgroundColor="#ffffff",t.border=".1em solid #000000",t.color="#b50000",t.bottom="0px",t.left="0px",t.margin="0px",t.zIndex="10000",t.textAlign="center",e.classList.add("firebase-emulator-warning"),document.body.appendChild(e)}"undefined"!=typeof console&&"function"==typeof console.info&&console.info("WARNING: You are using the Auth Emulator, which is intended for local testing only.  Do not use with production credentials."),"undefined"!=typeof window&&"undefined"!=typeof document&&("loading"===document.readyState?window.addEventListener("DOMContentLoaded",e):e())}()}function eE(e){let t=e.indexOf(":");return t<0?"":e.substr(0,t+1)}function eS(e){if(!e)return null;let t=Number(e);return isNaN(t)?null:t}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class ek{constructor(e,t){this.providerId=e,this.signInMethod=t}toJSON(){return I("not implemented")}_getIdTokenResponse(e){return I("not implemented")}_linkToIdToken(e,t){return I("not implemented")}_getReauthenticationResolver(e){return I("not implemented")}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function eA(e,t){return L(e,"POST","/v1/accounts:resetPassword",P(e,t))}async function eC(e,t){return L(e,"POST","/v1/accounts:update",t)}async function ex(e,t){return L(e,"POST","/v1/accounts:update",P(e,t))}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function eR(e,t){return F(e,"POST","/v1/accounts:signInWithPassword",P(e,t))}async function eD(e,t){return L(e,"POST","/v1/accounts:sendOobCode",P(e,t))}async function eN(e,t){return eD(e,t)}async function eO(e,t){return eD(e,t)}async function eP(e,t){return eD(e,t)}async function eL(e,t){return eD(e,t)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function eM(e,t){return F(e,"POST","/v1/accounts:signInWithEmailLink",P(e,t))}async function eF(e,t){return F(e,"POST","/v1/accounts:signInWithEmailLink",P(e,t))}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class eU extends ek{constructor(e,t,n,r=null){super("password",n),this._email=e,this._password=t,this._tenantId=r}static _fromEmailAndPassword(e,t){return new eU(e,t,"password")}static _fromEmailAndCode(e,t,n=null){return new eU(e,t,"emailLink",n)}toJSON(){return{email:this._email,password:this._password,signInMethod:this.signInMethod,tenantId:this._tenantId}}static fromJSON(e){let t="string"==typeof e?JSON.parse(e):e;if((null==t?void 0:t.email)&&(null==t?void 0:t.password)){if("password"===t.signInMethod)return this._fromEmailAndPassword(t.email,t.password);if("emailLink"===t.signInMethod)return this._fromEmailAndCode(t.email,t.password,t.tenantId)}return null}async _getIdTokenResponse(e){switch(this.signInMethod){case"password":return eR(e,{returnSecureToken:!0,email:this._email,password:this._password});case"emailLink":return eM(e,{email:this._email,oobCode:this._password});default:g(e,"internal-error")}}async _linkToIdToken(e,t){switch(this.signInMethod){case"password":return eC(e,{idToken:t,returnSecureToken:!0,email:this._email,password:this._password});case"emailLink":return eF(e,{idToken:t,email:this._email,oobCode:this._password});default:g(e,"internal-error")}}_getReauthenticationResolver(e){return this._getIdTokenResponse(e)}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function eV(e,t){return F(e,"POST","/v1/accounts:signInWithIdp",P(e,t))}class eq extends ek{constructor(){super(...arguments),this.pendingToken=null}static _fromParams(e){let t=new eq(e.providerId,e.signInMethod);return e.idToken||e.accessToken?(e.idToken&&(t.idToken=e.idToken),e.accessToken&&(t.accessToken=e.accessToken),e.nonce&&!e.pendingToken&&(t.nonce=e.nonce),e.pendingToken&&(t.pendingToken=e.pendingToken)):e.oauthToken&&e.oauthTokenSecret?(t.accessToken=e.oauthToken,t.secret=e.oauthTokenSecret):g("argument-error"),t}toJSON(){return{idToken:this.idToken,accessToken:this.accessToken,secret:this.secret,nonce:this.nonce,pendingToken:this.pendingToken,providerId:this.providerId,signInMethod:this.signInMethod}}static fromJSON(e){let t="string"==typeof e?JSON.parse(e):e,{providerId:n,signInMethod:r}=t,i=o(t,["providerId","signInMethod"]);if(!n||!r)return null;let s=new eq(n,r);return s.idToken=i.idToken||void 0,s.accessToken=i.accessToken||void 0,s.secret=i.secret,s.nonce=i.nonce,s.pendingToken=i.pendingToken||null,s}_getIdTokenResponse(e){let t=this.buildRequest();return eV(e,t)}_linkToIdToken(e,t){let n=this.buildRequest();return n.idToken=t,eV(e,n)}_getReauthenticationResolver(e){let t=this.buildRequest();return t.autoCreate=!1,eV(e,t)}buildRequest(){let e={requestUri:"http://localhost",returnSecureToken:!0};if(this.pendingToken)e.pendingToken=this.pendingToken;else{let t={};this.idToken&&(t.id_token=this.idToken),this.accessToken&&(t.access_token=this.accessToken),this.secret&&(t.oauth_token_secret=this.secret),t.providerId=this.providerId,this.nonce&&!this.pendingToken&&(t.nonce=this.nonce),e.postBody=(0,i.xO)(t)}return e}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function eB(e,t){return L(e,"POST","/v1/accounts:sendVerificationCode",P(e,t))}async function ej(e,t){return F(e,"POST","/v1/accounts:signInWithPhoneNumber",P(e,t))}async function e$(e,t){let n=await F(e,"POST","/v1/accounts:signInWithPhoneNumber",P(e,t));if(n.temporaryProof)throw q(e,"account-exists-with-different-credential",n);return n}let ez={USER_NOT_FOUND:"user-not-found"};async function eG(e,t){let n=Object.assign(Object.assign({},t),{operation:"REAUTH"});return F(e,"POST","/v1/accounts:signInWithPhoneNumber",P(e,n),ez)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class eK extends ek{constructor(e){super("phone","phone"),this.params=e}static _fromVerification(e,t){return new eK({verificationId:e,verificationCode:t})}static _fromTokenResponse(e,t){return new eK({phoneNumber:e,temporaryProof:t})}_getIdTokenResponse(e){return ej(e,this._makeVerificationRequest())}_linkToIdToken(e,t){return e$(e,Object.assign({idToken:t},this._makeVerificationRequest()))}_getReauthenticationResolver(e){return eG(e,this._makeVerificationRequest())}_makeVerificationRequest(){let{temporaryProof:e,phoneNumber:t,verificationId:n,verificationCode:r}=this.params;return e&&t?{temporaryProof:e,phoneNumber:t}:{sessionInfo:n,code:r}}toJSON(){let e={providerId:this.providerId};return this.params.phoneNumber&&(e.phoneNumber=this.params.phoneNumber),this.params.temporaryProof&&(e.temporaryProof=this.params.temporaryProof),this.params.verificationCode&&(e.verificationCode=this.params.verificationCode),this.params.verificationId&&(e.verificationId=this.params.verificationId),e}static fromJSON(e){"string"==typeof e&&(e=JSON.parse(e));let{verificationId:t,verificationCode:n,phoneNumber:r,temporaryProof:i}=e;return n||t||r||i?new eK({verificationId:t,verificationCode:n,phoneNumber:r,temporaryProof:i}):null}}class eH{constructor(e){var t,n,r,s,a,o;let l=(0,i.zd)((0,i.pd)(e)),u=null!==(t=l.apiKey)&&void 0!==t?t:null,c=null!==(n=l.oobCode)&&void 0!==n?n:null,h=/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function(e){switch(e){case"recoverEmail":return"RECOVER_EMAIL";case"resetPassword":return"PASSWORD_RESET";case"signIn":return"EMAIL_SIGNIN";case"verifyEmail":return"VERIFY_EMAIL";case"verifyAndChangeEmail":return"VERIFY_AND_CHANGE_EMAIL";case"revertSecondFactorAddition":return"REVERT_SECOND_FACTOR_ADDITION";default:return null}}(null!==(r=l.mode)&&void 0!==r?r:null);b(u&&c&&h,"argument-error"),this.apiKey=u,this.operation=h,this.code=c,this.continueUrl=null!==(s=l.continueUrl)&&void 0!==s?s:null,this.languageCode=null!==(a=l.languageCode)&&void 0!==a?a:null,this.tenantId=null!==(o=l.tenantId)&&void 0!==o?o:null}static parseLink(e){let t=function(e){let t=(0,i.zd)((0,i.pd)(e)).link,n=t?(0,i.zd)((0,i.pd)(t)).deep_link_id:null,r=(0,i.zd)((0,i.pd)(e)).deep_link_id,s=r?(0,i.zd)((0,i.pd)(r)).link:null;return s||r||n||t||e}(e);try{return new eH(t)}catch(n){return null}}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class eW{constructor(){this.providerId=eW.PROVIDER_ID}static credential(e,t){return eU._fromEmailAndPassword(e,t)}static credentialWithLink(e,t){let n=eH.parseLink(t);return b(n,"argument-error"),eU._fromEmailAndCode(e,n.code,n.tenantId)}}eW.PROVIDER_ID="password",eW.EMAIL_PASSWORD_SIGN_IN_METHOD="password",eW.EMAIL_LINK_SIGN_IN_METHOD="emailLink";/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class eQ{constructor(e){this.providerId=e,this.defaultLanguageCode=null,this.customParameters={}}setDefaultLanguage(e){this.defaultLanguageCode=e}setCustomParameters(e){return this.customParameters=e,this}getCustomParameters(){return this.customParameters}}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class eY extends eQ{constructor(){super(...arguments),this.scopes=[]}addScope(e){return this.scopes.includes(e)||this.scopes.push(e),this}getScopes(){return[...this.scopes]}}class eX extends eY{static credentialFromJSON(e){let t="string"==typeof e?JSON.parse(e):e;return b("providerId"in t&&"signInMethod"in t,"argument-error"),eq._fromParams(t)}credential(e){return this._credential(Object.assign(Object.assign({},e),{nonce:e.rawNonce}))}_credential(e){return b(e.idToken||e.accessToken,"argument-error"),eq._fromParams(Object.assign(Object.assign({},e),{providerId:this.providerId,signInMethod:this.providerId}))}static credentialFromResult(e){return eX.oauthCredentialFromTaggedObject(e)}static credentialFromError(e){return eX.oauthCredentialFromTaggedObject(e.customData||{})}static oauthCredentialFromTaggedObject({_tokenResponse:e}){if(!e)return null;let{oauthIdToken:t,oauthAccessToken:n,oauthTokenSecret:r,pendingToken:i,nonce:s,providerId:a}=e;if(!n&&!r&&!t&&!i||!a)return null;try{return new eX(a)._credential({idToken:t,accessToken:n,nonce:s,pendingToken:i})}catch(o){return null}}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class eJ extends eY{constructor(){super("facebook.com")}static credential(e){return eq._fromParams({providerId:eJ.PROVIDER_ID,signInMethod:eJ.FACEBOOK_SIGN_IN_METHOD,accessToken:e})}static credentialFromResult(e){return eJ.credentialFromTaggedObject(e)}static credentialFromError(e){return eJ.credentialFromTaggedObject(e.customData||{})}static credentialFromTaggedObject({_tokenResponse:e}){if(!e||!("oauthAccessToken"in e)||!e.oauthAccessToken)return null;try{return eJ.credential(e.oauthAccessToken)}catch(t){return null}}}eJ.FACEBOOK_SIGN_IN_METHOD="facebook.com",eJ.PROVIDER_ID="facebook.com";/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class eZ extends eY{constructor(){super("google.com"),this.addScope("profile")}static credential(e,t){return eq._fromParams({providerId:eZ.PROVIDER_ID,signInMethod:eZ.GOOGLE_SIGN_IN_METHOD,idToken:e,accessToken:t})}static credentialFromResult(e){return eZ.credentialFromTaggedObject(e)}static credentialFromError(e){return eZ.credentialFromTaggedObject(e.customData||{})}static credentialFromTaggedObject({_tokenResponse:e}){if(!e)return null;let{oauthIdToken:t,oauthAccessToken:n}=e;if(!t&&!n)return null;try{return eZ.credential(t,n)}catch(r){return null}}}eZ.GOOGLE_SIGN_IN_METHOD="google.com",eZ.PROVIDER_ID="google.com";/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class e0 extends eY{constructor(){super("github.com")}static credential(e){return eq._fromParams({providerId:e0.PROVIDER_ID,signInMethod:e0.GITHUB_SIGN_IN_METHOD,accessToken:e})}static credentialFromResult(e){return e0.credentialFromTaggedObject(e)}static credentialFromError(e){return e0.credentialFromTaggedObject(e.customData||{})}static credentialFromTaggedObject({_tokenResponse:e}){if(!e||!("oauthAccessToken"in e)||!e.oauthAccessToken)return null;try{return e0.credential(e.oauthAccessToken)}catch(t){return null}}}e0.GITHUB_SIGN_IN_METHOD="github.com",e0.PROVIDER_ID="github.com";class e1 extends ek{constructor(e,t){super(e,e),this.pendingToken=t}_getIdTokenResponse(e){let t=this.buildRequest();return eV(e,t)}_linkToIdToken(e,t){let n=this.buildRequest();return n.idToken=t,eV(e,n)}_getReauthenticationResolver(e){let t=this.buildRequest();return t.autoCreate=!1,eV(e,t)}toJSON(){return{signInMethod:this.signInMethod,providerId:this.providerId,pendingToken:this.pendingToken}}static fromJSON(e){let t="string"==typeof e?JSON.parse(e):e,{providerId:n,signInMethod:r,pendingToken:i}=t;return n&&r&&i&&n===r?new e1(n,i):null}static _create(e,t){return new e1(e,t)}buildRequest(){return{requestUri:"http://localhost",returnSecureToken:!0,pendingToken:this.pendingToken}}}class e2 extends eQ{constructor(e){b(e.startsWith("saml."),"argument-error"),super(e)}static credentialFromResult(e){return e2.samlCredentialFromTaggedObject(e)}static credentialFromError(e){return e2.samlCredentialFromTaggedObject(e.customData||{})}static credentialFromJSON(e){let t=e1.fromJSON(e);return b(t,"argument-error"),t}static samlCredentialFromTaggedObject({_tokenResponse:e}){if(!e)return null;let{pendingToken:t,providerId:n}=e;if(!t||!n)return null;try{return e1._create(n,t)}catch(r){return null}}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class e4 extends eY{constructor(){super("twitter.com")}static credential(e,t){return eq._fromParams({providerId:e4.PROVIDER_ID,signInMethod:e4.TWITTER_SIGN_IN_METHOD,oauthToken:e,oauthTokenSecret:t})}static credentialFromResult(e){return e4.credentialFromTaggedObject(e)}static credentialFromError(e){return e4.credentialFromTaggedObject(e.customData||{})}static credentialFromTaggedObject({_tokenResponse:e}){if(!e)return null;let{oauthAccessToken:t,oauthTokenSecret:n}=e;if(!t||!n)return null;try{return e4.credential(t,n)}catch(r){return null}}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function e3(e,t){return F(e,"POST","/v1/accounts:signUp",P(e,t))}e4.TWITTER_SIGN_IN_METHOD="twitter.com",e4.PROVIDER_ID="twitter.com";/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class e6{constructor(e){this.user=e.user,this.providerId=e.providerId,this._tokenResponse=e._tokenResponse,this.operationType=e.operationType}static async _fromIdTokenResponse(e,t,n,r=!1){let i=await en._fromIdTokenResponse(e,n,r),s=e5(n),a=new e6({user:i,providerId:s,_tokenResponse:n,operationType:t});return a}static async _forOperation(e,t,n){await e._updateTokensIfNecessary(n,!0);let r=e5(n);return new e6({user:e,providerId:r,_tokenResponse:n,operationType:t})}}function e5(e){return e.providerId?e.providerId:"phoneNumber"in e?"phone":null}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function e9(e){var t;let n=eb(e);if(await n._initializationPromise,null===(t=n.currentUser)||void 0===t?void 0:t.isAnonymous)return new e6({user:n.currentUser,providerId:null,operationType:"signIn"});let r=await e3(n,{returnSecureToken:!0}),i=await e6._fromIdTokenResponse(n,"signIn",r,!0);return await n._updateCurrentUser(i.user),i}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class e8 extends i.ZR{constructor(e,t,n,r){var i;super(t.code,t.message),this.operationType=n,this.user=r,Object.setPrototypeOf(this,e8.prototype),this.customData={appName:e.name,tenantId:null!==(i=e.tenantId)&&void 0!==i?i:void 0,_serverResponse:t.customData._serverResponse,operationType:n}}static _fromErrorAndOperation(e,t,n,r){return new e8(e,t,n,r)}}function e7(e,t,n,r){let i="reauthenticate"===t?n._getReauthenticationResolver(e):n._getIdTokenResponse(e);return i.catch(n=>{if("auth/multi-factor-auth-required"===n.code)throw e8._fromErrorAndOperation(e,n,t,r);throw n})}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function te(e){return new Set(e.map(({providerId:e})=>e).filter(e=>!!e))}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function tt(e,t){let n=(0,i.m9)(e);await tr(!0,n,t);let{providerUserInfo:r}=await j(n.auth,{idToken:await n.getIdToken(),deleteProvider:[t]}),s=te(r||[]);return n.providerData=n.providerData.filter(e=>s.has(e.providerId)),s.has("phone")||(n.phoneNumber=null),await n.auth._persistUserIfCurrent(n),n}async function tn(e,t,n=!1){let r=await W(e,t._linkToIdToken(e.auth,await e.getIdToken()),n);return e6._forOperation(e,"link",r)}async function tr(e,t,n){await X(t);let r=te(t.providerData);b(r.has(n)===e,t.auth,!1===e?"provider-already-linked":"no-such-provider")}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function ti(e,t,n=!1){let{auth:r}=e,i="reauthenticate";try{let s=await W(e,e7(r,i,t,e),n);b(s.idToken,r,"internal-error");let a=H(s.idToken);b(a,r,"internal-error");let{sub:o}=a;return b(e.uid===o,r,"user-mismatch"),e6._forOperation(e,i,s)}catch(l){throw(null==l?void 0:l.code)==="auth/user-not-found"&&g(r,"user-mismatch"),l}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function ts(e,t,n=!1){let r="signIn",i=await e7(e,r,t),s=await e6._fromIdTokenResponse(e,r,i);return n||await e._updateCurrentUser(s.user),s}async function ta(e,t){return ts(eb(e),t)}async function to(e,t){let n=(0,i.m9)(e);return await tr(!1,n,t.providerId),tn(n,t)}async function tl(e,t){return ti((0,i.m9)(e),t)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function tu(e,t){return F(e,"POST","/v1/accounts:signInWithCustomToken",P(e,t))}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function tc(e,t){let n=eb(e),r=await tu(n,{token:t,returnSecureToken:!0}),i=await e6._fromIdTokenResponse(n,"signIn",r);return await n._updateCurrentUser(i.user),i}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class th{constructor(e,t){this.factorId=e,this.uid=t.mfaEnrollmentId,this.enrollmentTime=new Date(t.enrolledAt).toUTCString(),this.displayName=t.displayName}static _fromServerResponse(e,t){return"phoneInfo"in t?td._fromServerResponse(e,t):g(e,"internal-error")}}class td extends th{constructor(e){super("phone",e),this.phoneNumber=e.phoneInfo}static _fromServerResponse(e,t){return new td(t)}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function tf(e,t,n){var r;b((null===(r=n.url)||void 0===r?void 0:r.length)>0,e,"invalid-continue-uri"),b(void 0===n.dynamicLinkDomain||n.dynamicLinkDomain.length>0,e,"invalid-dynamic-link-domain"),t.continueUrl=n.url,t.dynamicLinkDomain=n.dynamicLinkDomain,t.canHandleCodeInApp=n.handleCodeInApp,n.iOS&&(b(n.iOS.bundleId.length>0,e,"missing-ios-bundle-id"),t.iOSBundleId=n.iOS.bundleId),n.android&&(b(n.android.packageName.length>0,e,"missing-android-pkg-name"),t.androidInstallApp=n.android.installApp,t.androidMinimumVersionCode=n.android.minimumVersion,t.androidPackageName=n.android.packageName)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function tp(e,t,n){let r=(0,i.m9)(e),s={requestType:"PASSWORD_RESET",email:t};n&&tf(r,s,n),await eO(r,s)}async function tm(e,t,n){await eA((0,i.m9)(e),{oobCode:t,newPassword:n})}async function tg(e,t){await ex((0,i.m9)(e),{oobCode:t})}async function ty(e,t){let n=(0,i.m9)(e),r=await eA(n,{oobCode:t}),s=r.requestType;switch(b(s,n,"internal-error"),s){case"EMAIL_SIGNIN":break;case"VERIFY_AND_CHANGE_EMAIL":b(r.newEmail,n,"internal-error");break;case"REVERT_SECOND_FACTOR_ADDITION":b(r.mfaInfo,n,"internal-error");default:b(r.email,n,"internal-error")}let a=null;return r.mfaInfo&&(a=th._fromServerResponse(eb(n),r.mfaInfo)),{data:{email:("VERIFY_AND_CHANGE_EMAIL"===r.requestType?r.newEmail:r.email)||null,previousEmail:("VERIFY_AND_CHANGE_EMAIL"===r.requestType?r.email:r.newEmail)||null,multiFactorInfo:a},operation:s}}async function tv(e,t){let{data:n}=await ty((0,i.m9)(e),t);return n.email}async function tw(e,t,n){let r=eb(e),i=await e3(r,{returnSecureToken:!0,email:t,password:n}),s=await e6._fromIdTokenResponse(r,"signIn",i);return await r._updateCurrentUser(s.user),s}function t_(e,t,n){return ta((0,i.m9)(e),eW.credential(t,n))}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function tb(e,t,n){let r=(0,i.m9)(e),s={requestType:"EMAIL_SIGNIN",email:t};b(n.handleCodeInApp,r,"argument-error"),n&&tf(r,s,n),await eP(r,s)}function tI(e,t){let n=eH.parseLink(t);return(null==n?void 0:n.operation)==="EMAIL_SIGNIN"}async function tT(e,t,n){let r=(0,i.m9)(e),s=eW.credentialWithLink(t,n||k());return b(s._tenantId===(r.tenantId||null),r,"tenant-id-mismatch"),ta(r,s)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function tE(e,t){return L(e,"POST","/v1/accounts:createAuthUri",P(e,t))}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function tS(e,t){let n=A()?k():"http://localhost",{signinMethods:r}=await tE((0,i.m9)(e),{identifier:t,continueUri:n});return r||[]}async function tk(e,t){let n=(0,i.m9)(e),r=await e.getIdToken(),s={requestType:"VERIFY_EMAIL",idToken:r};t&&tf(n.auth,s,t);let{email:a}=await eN(n.auth,s);a!==e.email&&await e.reload()}async function tA(e,t,n){let r=(0,i.m9)(e),s=await e.getIdToken(),a={requestType:"VERIFY_AND_CHANGE_EMAIL",idToken:s,newEmail:t};n&&tf(r.auth,a,n);let{email:o}=await eL(r.auth,a);o!==e.email&&await e.reload()}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function tC(e,t){return L(e,"POST","/v1/accounts:update",t)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function tx(e,{displayName:t,photoURL:n}){if(void 0===t&&void 0===n)return;let r=(0,i.m9)(e),s=await r.getIdToken(),a=await W(r,tC(r.auth,{idToken:s,displayName:t,photoUrl:n,returnSecureToken:!0}));r.displayName=a.displayName||null,r.photoURL=a.photoUrl||null;let o=r.providerData.find(({providerId:e})=>"password"===e);o&&(o.displayName=r.displayName,o.photoURL=r.photoURL),await r._updateTokensIfNecessary(a)}function tR(e,t){return tN((0,i.m9)(e),t,null)}function tD(e,t){return tN((0,i.m9)(e),null,t)}async function tN(e,t,n){let{auth:r}=e,i=await e.getIdToken(),s={idToken:i,returnSecureToken:!0};t&&(s.email=t),n&&(s.password=n);let a=await W(e,eC(r,s));await e._updateTokensIfNecessary(a,!0)}class tO{constructor(e,t,n={}){this.isNewUser=e,this.providerId=t,this.profile=n}}class tP extends tO{constructor(e,t,n,r){super(e,t,n),this.username=r}}class tL extends tO{constructor(e,t){super(e,"facebook.com",t)}}class tM extends tP{constructor(e,t){super(e,"github.com",t,"string"==typeof(null==t?void 0:t.login)?null==t?void 0:t.login:null)}}class tF extends tO{constructor(e,t){super(e,"google.com",t)}}class tU extends tP{constructor(e,t,n){super(e,"twitter.com",t,n)}}function tV(e){let{user:t,_tokenResponse:n}=e;return t.isAnonymous&&!n?{providerId:null,isNewUser:!1,profile:null}:/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function(e){var t,n;if(!e)return null;let{providerId:r}=e,i=e.rawUserInfo?JSON.parse(e.rawUserInfo):{},s=e.isNewUser||"identitytoolkit#SignupNewUserResponse"===e.kind;if(!r&&(null==e?void 0:e.idToken)){let a=null===(n=null===(t=H(e.idToken))||void 0===t?void 0:t.firebase)||void 0===n?void 0:n.sign_in_provider;if(a)return new tO(s,"anonymous"!==a&&"custom"!==a?a:null)}if(!r)return null;switch(r){case"facebook.com":return new tL(s,i);case"github.com":return new tM(s,i);case"google.com":return new tF(s,i);case"twitter.com":return new tU(s,i,e.screenName||null);case"custom":case"anonymous":return new tO(s,null);default:return new tO(s,r,i)}}(n)}function tq(e,t,n,r){return(0,i.m9)(e).onAuthStateChanged(t,n,r)}class tB{constructor(e,t,n){this.type=e,this.credential=t,this.auth=n}static _fromIdtoken(e,t){return new tB("enroll",e,t)}static _fromMfaPendingCredential(e){return new tB("signin",e)}toJSON(){let e="enroll"===this.type?"idToken":"pendingCredential";return{multiFactorSession:{[e]:this.credential}}}static fromJSON(e){var t,n;if(null==e?void 0:e.multiFactorSession){if(null===(t=e.multiFactorSession)||void 0===t?void 0:t.pendingCredential)return tB._fromMfaPendingCredential(e.multiFactorSession.pendingCredential);if(null===(n=e.multiFactorSession)||void 0===n?void 0:n.idToken)return tB._fromIdtoken(e.multiFactorSession.idToken)}return null}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class tj{constructor(e,t,n){this.session=e,this.hints=t,this.signInResolver=n}static _fromError(e,t){let n=eb(e),r=t.customData._serverResponse,i=(r.mfaInfo||[]).map(e=>th._fromServerResponse(n,e));b(r.mfaPendingCredential,n,"internal-error");let s=tB._fromMfaPendingCredential(r.mfaPendingCredential);return new tj(s,i,async e=>{let i=await e._process(n,s);delete r.mfaInfo,delete r.mfaPendingCredential;let a=Object.assign(Object.assign({},r),{idToken:i.idToken,refreshToken:i.refreshToken});switch(t.operationType){case"signIn":let o=await e6._fromIdTokenResponse(n,t.operationType,a);return await n._updateCurrentUser(o.user),o;case"reauthenticate":return b(t.user,n,"internal-error"),e6._forOperation(t.user,t.operationType,a);default:g(n,"internal-error")}})}async resolveSignIn(e){return this.signInResolver(e)}}function t$(e,t){var n;let r=(0,i.m9)(e);return b(t.customData.operationType,r,"argument-error"),b(null===(n=t.customData._serverResponse)||void 0===n?void 0:n.mfaPendingCredential,r,"argument-error"),tj._fromError(r,t)}class tz{constructor(e){this.user=e,this.enrolledFactors=[],e._onReload(t=>{t.mfaInfo&&(this.enrolledFactors=t.mfaInfo.map(t=>th._fromServerResponse(e.auth,t)))})}static _fromUser(e){return new tz(e)}async getSession(){return tB._fromIdtoken(await this.user.getIdToken(),this.user.auth)}async enroll(e,t){let n=await this.getSession(),r=await W(this.user,e._process(this.user.auth,n,t));return await this.user._updateTokensIfNecessary(r),this.user.reload()}async unenroll(e){var t;let n="string"==typeof e?e:e.uid,r=await this.user.getIdToken(),i=await W(this.user,L(t=this.user.auth,"POST","/v2/accounts/mfaEnrollment:withdraw",P(t,{idToken:r,mfaEnrollmentId:n})));this.enrolledFactors=this.enrolledFactors.filter(({uid:e})=>e!==n),await this.user._updateTokensIfNecessary(i);try{await this.user.reload()}catch(s){if((null==s?void 0:s.code)!=="auth/user-token-expired")throw s}}}let tG=new WeakMap;function tK(e){let t=(0,i.m9)(e);return tG.has(t)||tG.set(t,tz._fromUser(t)),tG.get(t)}let tH="__sak";/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class tW{constructor(e,t){this.storageRetriever=e,this.type=t}_isAvailable(){try{if(!this.storage)return Promise.resolve(!1);return this.storage.setItem(tH,"1"),this.storage.removeItem(tH),Promise.resolve(!0)}catch(e){return Promise.resolve(!1)}}_set(e,t){return this.storage.setItem(e,JSON.stringify(t)),Promise.resolve()}_get(e){let t=this.storage.getItem(e);return Promise.resolve(t?JSON.parse(t):null)}_remove(e){return this.storage.removeItem(e),Promise.resolve()}get storage(){return this.storageRetriever()}}class tQ extends tW{constructor(){super(()=>window.localStorage,"LOCAL"),this.boundEventHandler=(e,t)=>this.onStorageEvent(e,t),this.listeners={},this.localCache={},this.pollTimer=null,this.safariLocalStorageNotSynced=/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function(){let e=(0,i.z$)();return eu(e)||em(e)}()&&function(){try{return!!(window&&window!==window.top)}catch(e){return!1}}(),this.fallbackToPolling=ey(),this._shouldAllowMigration=!0}forAllChangedKeys(e){for(let t of Object.keys(this.listeners)){let n=this.storage.getItem(t),r=this.localCache[t];n!==r&&e(t,r,n)}}onStorageEvent(e,t=!1){if(!e.key){this.forAllChangedKeys((e,t,n)=>{this.notifyListeners(e,n)});return}let n=e.key;if(t?this.detachListener():this.stopPolling(),this.safariLocalStorageNotSynced){let r=this.storage.getItem(n);if(e.newValue!==r)null!==e.newValue?this.storage.setItem(n,e.newValue):this.storage.removeItem(n);else if(this.localCache[n]===e.newValue&&!t)return}let s=()=>{let e=this.storage.getItem(n);(t||this.localCache[n]!==e)&&this.notifyListeners(n,e)},a=this.storage.getItem(n);(0,i.w1)()&&10===document.documentMode&&a!==e.newValue&&e.newValue!==e.oldValue?setTimeout(s,10):s()}notifyListeners(e,t){this.localCache[e]=t;let n=this.listeners[e];if(n)for(let r of Array.from(n))r(t?JSON.parse(t):t)}startPolling(){this.stopPolling(),this.pollTimer=setInterval(()=>{this.forAllChangedKeys((e,t,n)=>{this.onStorageEvent(new StorageEvent("storage",{key:e,oldValue:t,newValue:n}),!0)})},1e3)}stopPolling(){this.pollTimer&&(clearInterval(this.pollTimer),this.pollTimer=null)}attachListener(){window.addEventListener("storage",this.boundEventHandler)}detachListener(){window.removeEventListener("storage",this.boundEventHandler)}_addListener(e,t){0===Object.keys(this.listeners).length&&(this.fallbackToPolling?this.startPolling():this.attachListener()),this.listeners[e]||(this.listeners[e]=new Set,this.localCache[e]=this.storage.getItem(e)),this.listeners[e].add(t)}_removeListener(e,t){this.listeners[e]&&(this.listeners[e].delete(t),0===this.listeners[e].size&&delete this.listeners[e]),0===Object.keys(this.listeners).length&&(this.detachListener(),this.stopPolling())}async _set(e,t){await super._set(e,t),this.localCache[e]=JSON.stringify(t)}async _get(e){let t=await super._get(e);return this.localCache[e]=JSON.stringify(t),t}async _remove(e){await super._remove(e),delete this.localCache[e]}}tQ.type="LOCAL";let tY=tQ;/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class tX extends tW{constructor(){super(()=>window.sessionStorage,"SESSION")}_addListener(e,t){}_removeListener(e,t){}}tX.type="SESSION";let tJ=tX;/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class tZ{constructor(e){this.eventTarget=e,this.handlersMap={},this.boundEventHandler=this.handleEvent.bind(this)}static _getInstance(e){let t=this.receivers.find(t=>t.isListeningto(e));if(t)return t;let n=new tZ(e);return this.receivers.push(n),n}isListeningto(e){return this.eventTarget===e}async handleEvent(e){let{eventId:t,eventType:n,data:r}=e.data,i=this.handlersMap[n];if(!(null==i?void 0:i.size))return;e.ports[0].postMessage({status:"ack",eventId:t,eventType:n});let s=Array.from(i).map(async t=>t(e.origin,r)),a=await Promise.all(s.map(async e=>{try{let t=await e;return{fulfilled:!0,value:t}}catch(n){return{fulfilled:!1,reason:n}}}));e.ports[0].postMessage({status:"done",eventId:t,eventType:n,response:a})}_subscribe(e,t){0===Object.keys(this.handlersMap).length&&this.eventTarget.addEventListener("message",this.boundEventHandler),this.handlersMap[e]||(this.handlersMap[e]=new Set),this.handlersMap[e].add(t)}_unsubscribe(e,t){this.handlersMap[e]&&t&&this.handlersMap[e].delete(t),t&&0!==this.handlersMap[e].size||delete this.handlersMap[e],0===Object.keys(this.handlersMap).length&&this.eventTarget.removeEventListener("message",this.boundEventHandler)}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function t0(e="",t=10){let n="";for(let r=0;r<t;r++)n+=Math.floor(10*Math.random());return e+n}tZ.receivers=[];/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class t1{constructor(e){this.target=e,this.handlers=new Set}removeMessageHandler(e){e.messageChannel&&(e.messageChannel.port1.removeEventListener("message",e.onMessage),e.messageChannel.port1.close()),this.handlers.delete(e)}async _send(e,t,n=50){let r,i;let s="undefined"!=typeof MessageChannel?new MessageChannel:null;if(!s)throw Error("connection_unavailable");return new Promise((a,o)=>{let l=t0("",20);s.port1.start();let u=setTimeout(()=>{o(Error("unsupported_event"))},n);i={messageChannel:s,onMessage(e){if(e.data.eventId===l)switch(e.data.status){case"ack":clearTimeout(u),r=setTimeout(()=>{o(Error("timeout"))},3e3);break;case"done":clearTimeout(r),a(e.data.response);break;default:clearTimeout(u),clearTimeout(r),o(Error("invalid_response"))}}},this.handlers.add(i),s.port1.addEventListener("message",i.onMessage),this.target.postMessage({eventType:e,eventId:l,data:t},[s.port2])}).finally(()=>{i&&this.removeMessageHandler(i)})}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function t2(){return window}/**
 * @license
 * Copyright 2020 Google LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function t4(){return void 0!==t2().WorkerGlobalScope&&"function"==typeof t2().importScripts}async function t3(){if(!(null==navigator?void 0:navigator.serviceWorker))return null;try{let e=await navigator.serviceWorker.ready;return e.active}catch(t){return null}}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let t6="firebaseLocalStorageDb",t5="firebaseLocalStorage",t9="fbase_key";class t8{constructor(e){this.request=e}toPromise(){return new Promise((e,t)=>{this.request.addEventListener("success",()=>{e(this.request.result)}),this.request.addEventListener("error",()=>{t(this.request.error)})})}}function t7(e,t){return e.transaction([t5],t?"readwrite":"readonly").objectStore(t5)}function ne(){let e=indexedDB.open(t6,1);return new Promise((t,n)=>{e.addEventListener("error",()=>{n(e.error)}),e.addEventListener("upgradeneeded",()=>{let t=e.result;try{t.createObjectStore(t5,{keyPath:t9})}catch(r){n(r)}}),e.addEventListener("success",async()=>{let n=e.result;n.objectStoreNames.contains(t5)?t(n):(n.close(),await function(){let e=indexedDB.deleteDatabase(t6);return new t8(e).toPromise()}(),t(await ne()))})})}async function nt(e,t,n){let r=t7(e,!0).put({[t9]:t,value:n});return new t8(r).toPromise()}async function nn(e,t){let n=t7(e,!1).get(t),r=await new t8(n).toPromise();return void 0===r?null:r.value}function nr(e,t){let n=t7(e,!0).delete(t);return new t8(n).toPromise()}class ni{constructor(){this.type="LOCAL",this._shouldAllowMigration=!0,this.listeners={},this.localCache={},this.pollTimer=null,this.pendingWrites=0,this.receiver=null,this.sender=null,this.serviceWorkerReceiverAvailable=!1,this.activeServiceWorker=null,this._workerInitializationPromise=this.initializeServiceWorkerMessaging().then(()=>{},()=>{})}async _openDb(){return this.db||(this.db=await ne()),this.db}async _withRetries(e){let t=0;for(;;)try{let n=await this._openDb();return await e(n)}catch(r){if(t++>3)throw r;this.db&&(this.db.close(),this.db=void 0)}}async initializeServiceWorkerMessaging(){return t4()?this.initializeReceiver():this.initializeSender()}async initializeReceiver(){this.receiver=tZ._getInstance(t4()?self:null),this.receiver._subscribe("keyChanged",async(e,t)=>{let n=await this._poll();return{keyProcessed:n.includes(t.key)}}),this.receiver._subscribe("ping",async(e,t)=>["keyChanged"])}async initializeSender(){var e,t;if(this.activeServiceWorker=await t3(),!this.activeServiceWorker)return;this.sender=new t1(this.activeServiceWorker);let n=await this.sender._send("ping",{},800);n&&(null===(e=n[0])||void 0===e?void 0:e.fulfilled)&&(null===(t=n[0])||void 0===t?void 0:t.value.includes("keyChanged"))&&(this.serviceWorkerReceiverAvailable=!0)}async notifyServiceWorker(e){var t;if(this.sender&&this.activeServiceWorker&&((null===(t=null==navigator?void 0:navigator.serviceWorker)||void 0===t?void 0:t.controller)||null)===this.activeServiceWorker)try{await this.sender._send("keyChanged",{key:e},this.serviceWorkerReceiverAvailable?800:50)}catch(n){}}async _isAvailable(){try{if(!indexedDB)return!1;let e=await ne();return await nt(e,tH,"1"),await nr(e,tH),!0}catch(t){}return!1}async _withPendingWrite(e){this.pendingWrites++;try{await e()}finally{this.pendingWrites--}}async _set(e,t){return this._withPendingWrite(async()=>(await this._withRetries(n=>nt(n,e,t)),this.localCache[e]=t,this.notifyServiceWorker(e)))}async _get(e){let t=await this._withRetries(t=>nn(t,e));return this.localCache[e]=t,t}async _remove(e){return this._withPendingWrite(async()=>(await this._withRetries(t=>nr(t,e)),delete this.localCache[e],this.notifyServiceWorker(e)))}async _poll(){let e=await this._withRetries(e=>{let t=t7(e,!1).getAll();return new t8(t).toPromise()});if(!e||0!==this.pendingWrites)return[];let t=[],n=new Set;for(let{fbase_key:r,value:i}of e)n.add(r),JSON.stringify(this.localCache[r])!==JSON.stringify(i)&&(this.notifyListeners(r,i),t.push(r));for(let s of Object.keys(this.localCache))this.localCache[s]&&!n.has(s)&&(this.notifyListeners(s,null),t.push(s));return t}notifyListeners(e,t){this.localCache[e]=t;let n=this.listeners[e];if(n)for(let r of Array.from(n))r(t)}startPolling(){this.stopPolling(),this.pollTimer=setInterval(async()=>this._poll(),800)}stopPolling(){this.pollTimer&&(clearInterval(this.pollTimer),this.pollTimer=null)}_addListener(e,t){0===Object.keys(this.listeners).length&&this.startPolling(),this.listeners[e]||(this.listeners[e]=new Set,this._get(e)),this.listeners[e].add(t)}_removeListener(e,t){this.listeners[e]&&(this.listeners[e].delete(t),0===this.listeners[e].size&&delete this.listeners[e]),0===Object.keys(this.listeners).length&&this.stopPolling()}}ni.type="LOCAL";let ns=ni;/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function na(e){return(await L(e,"GET","/v1/recaptchaParams")).recaptchaSiteKey||""}function no(e){return new Promise((t,n)=>{var r,i;let s=document.createElement("script");s.setAttribute("src",e),s.onload=t,s.onerror=e=>{let t=y("internal-error");t.customData=e,n(t)},s.type="text/javascript",s.charset="UTF-8",(null!==(i=null===(r=document.getElementsByTagName("head"))||void 0===r?void 0:r[0])&&void 0!==i?i:document).appendChild(s)})}function nl(e){return`__${e}${Math.floor(1e6*Math.random())}`}class nu{constructor(e){this.auth=e,this.counter=1e12,this._widgets=new Map}render(e,t){let n=this.counter;return this._widgets.set(n,new nc(e,this.auth.name,t||{})),this.counter++,n}reset(e){var t;let n=e||1e12;null===(t=this._widgets.get(n))||void 0===t||t.delete(),this._widgets.delete(n)}getResponse(e){var t;return(null===(t=this._widgets.get(e||1e12))||void 0===t?void 0:t.getResponse())||""}async execute(e){var t;return null===(t=this._widgets.get(e||1e12))||void 0===t||t.execute(),""}}class nc{constructor(e,t,n){this.params=n,this.timerId=null,this.deleted=!1,this.responseToken=null,this.clickHandler=()=>{this.execute()};let r="string"==typeof e?document.getElementById(e):e;b(r,"argument-error",{appName:t}),this.container=r,this.isVisible="invisible"!==this.params.size,this.isVisible?this.execute():this.container.addEventListener("click",this.clickHandler)}getResponse(){return this.checkIfDeleted(),this.responseToken}delete(){this.checkIfDeleted(),this.deleted=!0,this.timerId&&(clearTimeout(this.timerId),this.timerId=null),this.container.removeEventListener("click",this.clickHandler)}execute(){this.checkIfDeleted(),this.timerId||(this.timerId=window.setTimeout(()=>{this.responseToken=function(e){let t=[],n="1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";for(let r=0;r<50;r++)t.push(n.charAt(Math.floor(Math.random()*n.length)));return t.join("")}(0);let{callback:e,"expired-callback":t}=this.params;if(e)try{e(this.responseToken)}catch(n){}this.timerId=window.setTimeout(()=>{if(this.timerId=null,this.responseToken=null,t)try{t()}catch(e){}this.isVisible&&this.execute()},6e4)},500))}checkIfDeleted(){if(this.deleted)throw Error("reCAPTCHA mock was already deleted!")}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let nh=nl("rcb"),nd=new x(3e4,6e4);class nf{constructor(){var e;this.hostLanguage="",this.counter=0,this.librarySeparatelyLoaded=!!(null===(e=t2().grecaptcha)||void 0===e?void 0:e.render)}load(e,t=""){return(b(t.length<=6&&/^\s*[a-zA-Z0-9\-]*\s*$/.test(t),e,"argument-error"),this.shouldResolveImmediately(t))?Promise.resolve(t2().grecaptcha):new Promise((n,r)=>{let s=t2().setTimeout(()=>{r(y(e,"network-request-failed"))},nd.get());t2()[nh]=()=>{t2().clearTimeout(s),delete t2()[nh];let i=t2().grecaptcha;if(!i){r(y(e,"internal-error"));return}let a=i.render;i.render=(e,t)=>{let n=a(e,t);return this.counter++,n},this.hostLanguage=t,n(i)};let a=`https://www.google.com/recaptcha/api.js??${(0,i.xO)({onload:nh,render:"explicit",hl:t})}`;no(a).catch(()=>{clearTimeout(s),r(y(e,"internal-error"))})})}clearedOneInstance(){this.counter--}shouldResolveImmediately(e){var t;return!!(null===(t=t2().grecaptcha)||void 0===t?void 0:t.render)&&(e===this.hostLanguage||this.counter>0||this.librarySeparatelyLoaded)}}class np{async load(e){return new nu(e)}clearedOneInstance(){}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let nm="recaptcha",ng={theme:"light",type:"image"};class ny{constructor(e,t=Object.assign({},ng),n){this.parameters=t,this.type=nm,this.destroyed=!1,this.widgetId=null,this.tokenChangeListeners=new Set,this.renderPromise=null,this.recaptcha=null,this.auth=eb(n),this.isInvisible="invisible"===this.parameters.size,b("undefined"!=typeof document,this.auth,"operation-not-supported-in-this-environment");let r="string"==typeof e?document.getElementById(e):e;b(r,this.auth,"argument-error"),this.container=r,this.parameters.callback=this.makeTokenCallback(this.parameters.callback),this._recaptchaLoader=this.auth.settings.appVerificationDisabledForTesting?new np:new nf,this.validateStartingState()}async verify(){this.assertNotDestroyed();let e=await this.render(),t=this.getAssertedRecaptcha(),n=t.getResponse(e);return n||new Promise(n=>{let r=e=>{e&&(this.tokenChangeListeners.delete(r),n(e))};this.tokenChangeListeners.add(r),this.isInvisible&&t.execute(e)})}render(){try{this.assertNotDestroyed()}catch(e){return Promise.reject(e)}return this.renderPromise||(this.renderPromise=this.makeRenderPromise().catch(e=>{throw this.renderPromise=null,e})),this.renderPromise}_reset(){this.assertNotDestroyed(),null!==this.widgetId&&this.getAssertedRecaptcha().reset(this.widgetId)}clear(){this.assertNotDestroyed(),this.destroyed=!0,this._recaptchaLoader.clearedOneInstance(),this.isInvisible||this.container.childNodes.forEach(e=>{this.container.removeChild(e)})}validateStartingState(){b(!this.parameters.sitekey,this.auth,"argument-error"),b(this.isInvisible||!this.container.hasChildNodes(),this.auth,"argument-error"),b("undefined"!=typeof document,this.auth,"operation-not-supported-in-this-environment")}makeTokenCallback(e){return t=>{if(this.tokenChangeListeners.forEach(e=>e(t)),"function"==typeof e)e(t);else if("string"==typeof e){let n=t2()[e];"function"==typeof n&&n(t)}}}assertNotDestroyed(){b(!this.destroyed,this.auth,"internal-error")}async makeRenderPromise(){if(await this.init(),!this.widgetId){let e=this.container;if(!this.isInvisible){let t=document.createElement("div");e.appendChild(t),e=t}this.widgetId=this.getAssertedRecaptcha().render(e,this.parameters)}return this.widgetId}async init(){let e;b(A()&&!t4(),this.auth,"internal-error"),await (e=null,new Promise(t=>{if("complete"===document.readyState){t();return}e=()=>t(),window.addEventListener("load",e)}).catch(t=>{throw e&&window.removeEventListener("load",e),t})),this.recaptcha=await this._recaptchaLoader.load(this.auth,this.auth.languageCode||void 0);let t=await na(this.auth);b(t,this.auth,"internal-error"),this.parameters.sitekey=t}getAssertedRecaptcha(){return b(this.recaptcha,this.auth,"internal-error"),this.recaptcha}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class nv{constructor(e,t){this.verificationId=e,this.onConfirmation=t}confirm(e){let t=eK._fromVerification(this.verificationId,e);return this.onConfirmation(t)}}async function nw(e,t,n){let r=eb(e),s=await nI(r,t,(0,i.m9)(n));return new nv(s,e=>ta(r,e))}async function n_(e,t,n){let r=(0,i.m9)(e);await tr(!1,r,"phone");let s=await nI(r.auth,t,(0,i.m9)(n));return new nv(s,e=>to(r,e))}async function nb(e,t,n){let r=(0,i.m9)(e),s=await nI(r.auth,t,(0,i.m9)(n));return new nv(s,e=>tl(r,e))}async function nI(e,t,n){var r,i,s;let a=await n.verify();try{let o;if(b("string"==typeof a,e,"argument-error"),b(n.type===nm,e,"argument-error"),o="string"==typeof t?{phoneNumber:t}:t,"session"in o){let l=o.session;if("phoneNumber"in o){b("enroll"===l.type,e,"internal-error");let u=await (i={idToken:l.credential,phoneEnrollmentInfo:{phoneNumber:o.phoneNumber,recaptchaToken:a}},L(e,"POST","/v2/accounts/mfaEnrollment:start",P(e,i)));return u.phoneSessionInfo.sessionInfo}{b("signin"===l.type,e,"internal-error");let c=(null===(r=o.multiFactorHint)||void 0===r?void 0:r.uid)||o.multiFactorUid;b(c,e,"missing-multi-factor-info");let h=await (s={mfaPendingCredential:l.credential,mfaEnrollmentId:c,phoneSignInInfo:{recaptchaToken:a}},L(e,"POST","/v2/accounts/mfaSignIn:start",P(e,s)));return h.phoneResponseInfo.sessionInfo}}{let{sessionInfo:d}=await eB(e,{phoneNumber:o.phoneNumber,recaptchaToken:a});return d}}finally{n._reset()}}async function nT(e,t){await tn((0,i.m9)(e),t)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class nE{constructor(e){this.providerId=nE.PROVIDER_ID,this.auth=eb(e)}verifyPhoneNumber(e,t){return nI(this.auth,e,(0,i.m9)(t))}static credential(e,t){return eK._fromVerification(e,t)}static credentialFromResult(e){return nE.credentialFromTaggedObject(e)}static credentialFromError(e){return nE.credentialFromTaggedObject(e.customData||{})}static credentialFromTaggedObject({_tokenResponse:e}){if(!e)return null;let{phoneNumber:t,temporaryProof:n}=e;return t&&n?eK._fromTokenResponse(t,n):null}}/**
 * @license
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function nS(e,t){return t?S(t):(b(e._popupRedirectResolver,e,"argument-error"),e._popupRedirectResolver)}nE.PROVIDER_ID="phone",nE.PHONE_SIGN_IN_METHOD="phone";/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class nk extends ek{constructor(e){super("custom","custom"),this.params=e}_getIdTokenResponse(e){return eV(e,this._buildIdpRequest())}_linkToIdToken(e,t){return eV(e,this._buildIdpRequest(t))}_getReauthenticationResolver(e){return eV(e,this._buildIdpRequest())}_buildIdpRequest(e){let t={requestUri:this.params.requestUri,sessionId:this.params.sessionId,postBody:this.params.postBody,tenantId:this.params.tenantId,pendingToken:this.params.pendingToken,returnSecureToken:!0,returnIdpCredential:!0};return e&&(t.idToken=e),t}}function nA(e){return ts(e.auth,new nk(e),e.bypassAuthState)}function nC(e){let{auth:t,user:n}=e;return b(n,t,"internal-error"),ti(n,new nk(e),e.bypassAuthState)}async function nx(e){let{auth:t,user:n}=e;return b(n,t,"internal-error"),tn(n,new nk(e),e.bypassAuthState)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class nR{constructor(e,t,n,r,i=!1){this.auth=e,this.resolver=n,this.user=r,this.bypassAuthState=i,this.pendingPromise=null,this.eventManager=null,this.filter=Array.isArray(t)?t:[t]}execute(){return new Promise(async(e,t)=>{this.pendingPromise={resolve:e,reject:t};try{this.eventManager=await this.resolver._initialize(this.auth),await this.onExecution(),this.eventManager.registerConsumer(this)}catch(n){this.reject(n)}})}async onAuthEvent(e){let{urlResponse:t,sessionId:n,postBody:r,tenantId:i,error:s,type:a}=e;if(s){this.reject(s);return}let o={auth:this.auth,requestUri:t,sessionId:n,tenantId:i||void 0,postBody:r||void 0,user:this.user,bypassAuthState:this.bypassAuthState};try{this.resolve(await this.getIdpTask(a)(o))}catch(l){this.reject(l)}}onError(e){this.reject(e)}getIdpTask(e){switch(e){case"signInViaPopup":case"signInViaRedirect":return nA;case"linkViaPopup":case"linkViaRedirect":return nx;case"reauthViaPopup":case"reauthViaRedirect":return nC;default:g(this.auth,"internal-error")}}resolve(e){T(this.pendingPromise,"Pending promise was never set"),this.pendingPromise.resolve(e),this.unregisterAndCleanUp()}reject(e){T(this.pendingPromise,"Pending promise was never set"),this.pendingPromise.reject(e),this.unregisterAndCleanUp()}unregisterAndCleanUp(){this.eventManager&&this.eventManager.unregisterConsumer(this),this.pendingPromise=null,this.cleanUp()}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let nD=new x(2e3,1e4);async function nN(e,t,n){let r=eb(e);w(e,t,eQ);let i=nS(r,n),s=new nL(r,"signInViaPopup",t,i);return s.executeNotNull()}async function nO(e,t,n){let r=(0,i.m9)(e);w(r.auth,t,eQ);let s=nS(r.auth,n),a=new nL(r.auth,"reauthViaPopup",t,s,r);return a.executeNotNull()}async function nP(e,t,n){let r=(0,i.m9)(e);w(r.auth,t,eQ);let s=nS(r.auth,n),a=new nL(r.auth,"linkViaPopup",t,s,r);return a.executeNotNull()}class nL extends nR{constructor(e,t,n,r,i){super(e,t,r,i),this.provider=n,this.authWindow=null,this.pollId=null,nL.currentPopupAction&&nL.currentPopupAction.cancel(),nL.currentPopupAction=this}async executeNotNull(){let e=await this.execute();return b(e,this.auth,"internal-error"),e}async onExecution(){T(1===this.filter.length,"Popup operations only handle one event");let e=t0();this.authWindow=await this.resolver._openPopup(this.auth,this.provider,this.filter[0],e),this.authWindow.associatedEvent=e,this.resolver._originValidation(this.auth).catch(e=>{this.reject(e)}),this.resolver._isIframeWebStorageSupported(this.auth,e=>{e||this.reject(y(this.auth,"web-storage-unsupported"))}),this.pollUserCancellation()}get eventId(){var e;return(null===(e=this.authWindow)||void 0===e?void 0:e.associatedEvent)||null}cancel(){this.reject(y(this.auth,"cancelled-popup-request"))}cleanUp(){this.authWindow&&this.authWindow.close(),this.pollId&&window.clearTimeout(this.pollId),this.authWindow=null,this.pollId=null,nL.currentPopupAction=null}pollUserCancellation(){let e=()=>{var t,n;if(null===(n=null===(t=this.authWindow)||void 0===t?void 0:t.window)||void 0===n?void 0:n.closed){this.pollId=window.setTimeout(()=>{this.pollId=null,this.reject(y(this.auth,"popup-closed-by-user"))},2e3);return}this.pollId=window.setTimeout(e,nD.get())};e()}}nL.currentPopupAction=null;let nM=new Map;class nF extends nR{constructor(e,t,n=!1){super(e,["signInViaRedirect","linkViaRedirect","reauthViaRedirect","unknown"],t,void 0,n),this.eventId=null}async execute(){let e=nM.get(this.auth._key());if(!e){try{let t=await nU(this.resolver,this.auth),n=t?await super.execute():null;e=()=>Promise.resolve(n)}catch(r){e=()=>Promise.reject(r)}nM.set(this.auth._key(),e)}return this.bypassAuthState||nM.set(this.auth._key(),()=>Promise.resolve(null)),e()}async onAuthEvent(e){if("signInViaRedirect"===e.type)return super.onAuthEvent(e);if("unknown"===e.type){this.resolve(null);return}if(e.eventId){let t=await this.auth._redirectUserForId(e.eventId);if(t)return this.user=t,super.onAuthEvent(e);this.resolve(null)}}async onExecution(){}cleanUp(){}}async function nU(e,t){let n=n$(t),r=nj(e);if(!await r._isAvailable())return!1;let i=await r._get(n)==="true";return await r._remove(n),i}async function nV(e,t){return nj(e)._set(n$(t),"true")}function nq(){nM.clear()}function nB(e,t){nM.set(e._key(),t)}function nj(e){return S(e._redirectPersistence)}function n$(e){return es("pendingRedirect",e.config.apiKey,e.name)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function nz(e,t,n){return nG(e,t,n)}async function nG(e,t,n){let r=eb(e);w(e,t,eQ);let i=nS(r,n);return await nV(i,r),i._openRedirect(r,t,"signInViaRedirect")}function nK(e,t,n){return nH(e,t,n)}async function nH(e,t,n){let r=(0,i.m9)(e);w(r.auth,t,eQ);let s=nS(r.auth,n);await nV(s,r.auth);let a=await nJ(r);return s._openRedirect(r.auth,t,"reauthViaRedirect",a)}function nW(e,t,n){return nQ(e,t,n)}async function nQ(e,t,n){let r=(0,i.m9)(e);w(r.auth,t,eQ);let s=nS(r.auth,n);await tr(!1,r,t.providerId),await nV(s,r.auth);let a=await nJ(r);return s._openRedirect(r.auth,t,"linkViaRedirect",a)}async function nY(e,t){return await eb(e)._initializationPromise,nX(e,t,!1)}async function nX(e,t,n=!1){let r=eb(e),i=nS(r,t),s=new nF(r,i,n),a=await s.execute();return a&&!n&&(delete a.user._redirectEventId,await r._persistUserIfCurrent(a.user),await r._setRedirectUser(null,t)),a}async function nJ(e){let t=t0(`${e.uid}:::`);return e._redirectEventId=t,await e.auth._setRedirectUser(e),await e.auth._persistUserIfCurrent(e),t}class nZ{constructor(e){this.auth=e,this.cachedEventUids=new Set,this.consumers=new Set,this.queuedRedirectEvent=null,this.hasHandledPotentialRedirect=!1,this.lastProcessedEventTime=Date.now()}registerConsumer(e){this.consumers.add(e),this.queuedRedirectEvent&&this.isEventForConsumer(this.queuedRedirectEvent,e)&&(this.sendToConsumer(this.queuedRedirectEvent,e),this.saveEventToCache(this.queuedRedirectEvent),this.queuedRedirectEvent=null)}unregisterConsumer(e){this.consumers.delete(e)}onEvent(e){if(this.hasEventBeenHandled(e))return!1;let t=!1;return this.consumers.forEach(n=>{this.isEventForConsumer(e,n)&&(t=!0,this.sendToConsumer(e,n),this.saveEventToCache(e))}),this.hasHandledPotentialRedirect||!function(e){switch(e.type){case"signInViaRedirect":case"linkViaRedirect":case"reauthViaRedirect":return!0;case"unknown":return n1(e);default:return!1}}(e)||(this.hasHandledPotentialRedirect=!0,t||(this.queuedRedirectEvent=e,t=!0)),t}sendToConsumer(e,t){var n;if(e.error&&!n1(e)){let r=(null===(n=e.error.code)||void 0===n?void 0:n.split("auth/")[1])||"internal-error";t.onError(y(this.auth,r))}else t.onAuthEvent(e)}isEventForConsumer(e,t){let n=null===t.eventId||!!e.eventId&&e.eventId===t.eventId;return t.filter.includes(e.type)&&n}hasEventBeenHandled(e){return Date.now()-this.lastProcessedEventTime>=6e5&&this.cachedEventUids.clear(),this.cachedEventUids.has(n0(e))}saveEventToCache(e){this.cachedEventUids.add(n0(e)),this.lastProcessedEventTime=Date.now()}}function n0(e){return[e.type,e.eventId,e.sessionId,e.tenantId].filter(e=>e).join("-")}function n1({type:e,error:t}){return"unknown"===e&&(null==t?void 0:t.code)==="auth/no-auth-event"}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function n2(e,t={}){return L(e,"GET","/v1/projects",t)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let n4=/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,n3=/^https?/;async function n6(e){if(e.config.emulator)return;let{authorizedDomains:t}=await n2(e);for(let n of t)try{if(function(e){let t=k(),{protocol:n,hostname:r}=new URL(t);if(e.startsWith("chrome-extension://")){let i=new URL(e);return""===i.hostname&&""===r?"chrome-extension:"===n&&e.replace("chrome-extension://","")===t.replace("chrome-extension://",""):"chrome-extension:"===n&&i.hostname===r}if(!n3.test(n))return!1;if(n4.test(e))return r===e;let s=e.replace(/\./g,"\\."),a=RegExp("^(.+\\."+s+"|"+s+")$","i");return a.test(r)}(n))return}catch(r){}g(e,"unauthorized-domain")}/**
 * @license
 * Copyright 2020 Google LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let n5=new x(3e4,6e4);function n9(){let e=t2().___jsl;if(null==e?void 0:e.H){for(let t of Object.keys(e.H))if(e.H[t].r=e.H[t].r||[],e.H[t].L=e.H[t].L||[],e.H[t].r=[...e.H[t].L],e.CP)for(let n=0;n<e.CP.length;n++)e.CP[n]=null}}let n8=null,n7=new x(5e3,15e3),re={style:{position:"absolute",top:"-100px",width:"1px",height:"1px"},"aria-hidden":"true",tabindex:"-1"},rt=new Map([["identitytoolkit.googleapis.com","p"],["staging-identitytoolkit.sandbox.googleapis.com","s"],["test-identitytoolkit.sandbox.googleapis.com","t"]]);async function rn(e){let t=await (n8=n8||new Promise((t,n)=>{var r,i,s;function a(){n9(),gapi.load("gapi.iframes",{callback:()=>{t(gapi.iframes.getContext())},ontimeout:()=>{n9(),n(y(e,"network-request-failed"))},timeout:n5.get()})}if(null===(i=null===(r=t2().gapi)||void 0===r?void 0:r.iframes)||void 0===i?void 0:i.Iframe)t(gapi.iframes.getContext());else if(null===(s=t2().gapi)||void 0===s?void 0:s.load)a();else{let o=nl("iframefcb");return t2()[o]=()=>{gapi.load?a():n(y(e,"network-request-failed"))},no(`https://apis.google.com/js/api.js?onload=${o}`).catch(e=>n(e))}}).catch(e=>{throw n8=null,e})),n=t2().gapi;return b(n,e,"internal-error"),t.open({where:document.body,url:function(e){let t=e.config;b(t.authDomain,e,"auth-domain-config-required");let n=t.emulator?R(t,"emulator/auth/iframe"):`https://${e.config.authDomain}/__/auth/iframe`,r={apiKey:t.apiKey,appName:e.name,v:s.SDK_VERSION},a=rt.get(e.config.apiHost);a&&(r.eid=a);let o=e._getFrameworks();return o.length&&(r.fw=o.join(",")),`${n}?${(0,i.xO)(r).slice(1)}`}(e),messageHandlersFilter:n.iframes.CROSS_ORIGIN_IFRAMES_FILTER,attributes:re,dontclear:!0},t=>new Promise(async(n,r)=>{await t.restyle({setHideOnLeave:!1});let i=y(e,"network-request-failed"),s=t2().setTimeout(()=>{r(i)},n7.get());function a(){t2().clearTimeout(s),n(t)}t.ping(a).then(a,()=>{r(i)})}))}/**
 * @license
 * Copyright 2020 Google LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let rr={location:"yes",resizable:"yes",statusbar:"yes",toolbar:"no"};class ri{constructor(e){this.window=e,this.associatedEvent=null}close(){if(this.window)try{this.window.close()}catch(e){}}}function rs(e,t,n,r,a,o){b(e.config.authDomain,e,"auth-domain-config-required"),b(e.config.apiKey,e,"invalid-api-key");let l={apiKey:e.config.apiKey,appName:e.name,authType:n,redirectUrl:r,v:s.SDK_VERSION,eventId:a};if(t instanceof eQ)for(let[u,c]of(t.setDefaultLanguage(e.languageCode),l.providerId=t.providerId||"",(0,i.xb)(t.getCustomParameters())||(l.customParameters=JSON.stringify(t.getCustomParameters())),Object.entries(o||{})))l[u]=c;if(t instanceof eY){let h=t.getScopes().filter(e=>""!==e);h.length>0&&(l.scopes=h.join(","))}e.tenantId&&(l.tid=e.tenantId);let d=l;for(let f of Object.keys(d))void 0===d[f]&&delete d[f];return`${function({config:e}){return e.emulator?R(e,"emulator/auth/handler"):`https://${e.authDomain}/__/auth/handler`}(e)}?${(0,i.xO)(d).slice(1)}`}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let ra="webStorageSupport",ro=class{constructor(){this.eventManagers={},this.iframes={},this.originValidationPromises={},this._redirectPersistence=tJ,this._completeRedirectFn=nX,this._overrideRedirectResult=nB}async _openPopup(e,t,n,r){var s;T(null===(s=this.eventManagers[e._key()])||void 0===s?void 0:s.manager,"_initialize() not called before _openPopup()");let a=rs(e,t,n,k(),r);return function(e,t,n,r=500,s=600){let a=Math.max((window.screen.availHeight-s)/2,0).toString(),o=Math.max((window.screen.availWidth-r)/2,0).toString(),l="",u=Object.assign(Object.assign({},rr),{width:r.toString(),height:s.toString(),top:a,left:o}),c=(0,i.z$)().toLowerCase();n&&(l=ec(c)?"_blank":n),el(c)&&(t=t||"http://localhost",u.scrollbars="yes");let h=Object.entries(u).reduce((e,[t,n])=>`${e}${t}=${n},`,"");if(function(e=(0,i.z$)()){var t;return em(e)&&!!(null===(t=window.navigator)||void 0===t?void 0:t.standalone)}(c)&&"_self"!==l)return function(e,t){let n=document.createElement("a");n.href=e,n.target=t;let r=document.createEvent("MouseEvent");r.initMouseEvent("click",!0,!0,window,1,0,0,0,0,!1,!1,!1,!1,1,null),n.dispatchEvent(r)}(t||"",l),new ri(null);let d=window.open(t||"",l,h);b(d,e,"popup-blocked");try{d.focus()}catch(f){}return new ri(d)}(e,a,t0())}async _openRedirect(e,t,n,r){var i;return await this._originValidation(e),i=rs(e,t,n,k(),r),t2().location.href=i,new Promise(()=>{})}_initialize(e){let t=e._key();if(this.eventManagers[t]){let{manager:n,promise:r}=this.eventManagers[t];return n?Promise.resolve(n):(T(r,"If manager is not set, promise should be"),r)}let i=this.initAndGetManager(e);return this.eventManagers[t]={promise:i},i.catch(()=>{delete this.eventManagers[t]}),i}async initAndGetManager(e){let t=await rn(e),n=new nZ(e);return t.register("authEvent",t=>{b(null==t?void 0:t.authEvent,e,"invalid-auth-event");let r=n.onEvent(t.authEvent);return{status:r?"ACK":"ERROR"}},gapi.iframes.CROSS_ORIGIN_IFRAMES_FILTER),this.eventManagers[e._key()]={manager:n},this.iframes[e._key()]=t,n}_isIframeWebStorageSupported(e,t){let n=this.iframes[e._key()];n.send(ra,{type:ra},n=>{var r;let i=null===(r=null==n?void 0:n[0])||void 0===r?void 0:r[ra];void 0!==i&&t(!!i),g(e,"internal-error")},gapi.iframes.CROSS_ORIGIN_IFRAMES_FILTER)}_originValidation(e){let t=e._key();return this.originValidationPromises[t]||(this.originValidationPromises[t]=n6(e)),this.originValidationPromises[t]}get _shouldInitProactively(){return ey()||eu()||em()}};class rl{constructor(e){this.factorId=e}_process(e,t,n){switch(t.type){case"enroll":return this._finalizeEnroll(e,t.credential,n);case"signin":return this._finalizeSignIn(e,t.credential);default:return I("unexpected MultiFactorSessionType")}}}class ru extends rl{constructor(e){super("phone"),this.credential=e}static _fromCredential(e){return new ru(e)}_finalizeEnroll(e,t,n){return L(e,"POST","/v2/accounts/mfaEnrollment:finalize",P(e,{idToken:t,displayName:n,phoneVerificationInfo:this.credential._makeVerificationRequest()}))}_finalizeSignIn(e,t){return L(e,"POST","/v2/accounts/mfaSignIn:finalize",P(e,{mfaPendingCredential:t,phoneVerificationInfo:this.credential._makeVerificationRequest()}))}}class rc{constructor(){}static assertion(e){return ru._fromCredential(e)}}rc.FACTOR_ID="phone";var rh="@firebase/auth",rd="0.21.0";/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class rf{constructor(e){this.auth=e,this.internalListeners=new Map}getUid(){var e;return this.assertAuthConfigured(),(null===(e=this.auth.currentUser)||void 0===e?void 0:e.uid)||null}async getToken(e){if(this.assertAuthConfigured(),await this.auth._initializationPromise,!this.auth.currentUser)return null;let t=await this.auth.currentUser.getIdToken(e);return{accessToken:t}}addAuthTokenListener(e){if(this.assertAuthConfigured(),this.internalListeners.has(e))return;let t=this.auth.onIdTokenChanged(t=>{e((null==t?void 0:t.stsTokenManager.accessToken)||null)});this.internalListeners.set(e,t),this.updateProactiveRefresh()}removeAuthTokenListener(e){this.assertAuthConfigured();let t=this.internalListeners.get(e);t&&(this.internalListeners.delete(e),t(),this.updateProactiveRefresh())}assertAuthConfigured(){b(this.auth._initializationPromise,"dependent-sdk-initialized-before-auth")}updateProactiveRefresh(){this.internalListeners.size>0?this.auth._startProactiveRefresh():this.auth._stopProactiveRefresh()}}(0,i.Pz)("authIdTokenMaxAge"),r="Browser",(0,s._registerComponent)(new l.wA("auth",(e,{options:t})=>{let n=e.getProvider("app").getImmediate(),i=e.getProvider("heartbeat"),{apiKey:s,authDomain:a}=n.options;return((e,n)=>{b(s&&!s.includes(":"),"invalid-api-key",{appName:e.name}),b(!(null==a?void 0:a.includes(":")),"argument-error",{appName:e.name});let i={apiKey:s,authDomain:a,clientPlatform:r,apiHost:"identitytoolkit.googleapis.com",tokenApiHost:"securetoken.googleapis.com",apiScheme:"https",sdkClientVersion:ev(r)},o=new e_(e,n,i);return function(e,t){let n=(null==t?void 0:t.persistence)||[],r=(Array.isArray(n)?n:[n]).map(S);(null==t?void 0:t.errorMap)&&e._updateErrorMap(t.errorMap),e._initializeWithPersistence(r,null==t?void 0:t.popupRedirectResolver)}(o,t),o})(n,i)},"PUBLIC").setInstantiationMode("EXPLICIT").setInstanceCreatedCallback((e,t,n)=>{let r=e.getProvider("auth-internal");r.initialize()})),(0,s._registerComponent)(new l.wA("auth-internal",e=>{let t=eb(e.getProvider("auth").getImmediate());return new rf(t)},"PRIVATE").setInstantiationMode("EXPLICIT")),(0,s.registerVersion)(rh,rd,/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function(e){switch(e){case"Node":return"node";case"ReactNative":return"rn";case"Worker":return"webworker";case"Cordova":return"cordova";default:return}}(r)),(0,s.registerVersion)(rh,rd,"esm2017")},1294:function(e,t,n){"use strict";n.d(t,{u7:function(){return hx},Jj:function(){return cF},IX:function(){return cT},my:function(){return u6},xU:function(){return hO},Lz:function(){return cU},WA:function(){return nQ},F8:function(){return cq},$q:function(){return hP},W:function(){return hL},EK:function(){return n8},PU:function(){return hZ},l7:function(){return rD},Ky:function(){return ri},Xb:function(){return rr},Cf:function(){return uZ},K9:function(){return nH},Me:function(){return rU},yq:function(){return nz},Wi:function(){return uQ},ET:function(){return hH},Ab:function(){return h5},vr:function(){return h6},Fc:function(){return cR},hJ:function(){return u8},B$:function(){return u7},at:function(){return u3},oe:function(){return hK},AK:function(){return h4},TF:function(){return cO},JU:function(){return ce},ST:function(){return cA},fH:function(){return cC},Ix:function(){return cN},Wu:function(){return hT},Lx:function(){return hI},qY:function(){return cS},GL:function(){return hY},QT:function(){return hF},kl:function(){return hV},Xk:function(){return hq},PL:function(){return hB},UQ:function(){return hj},zN:function(){return h$},nP:function(){return h9},b9:function(){return hg},vh:function(){return hy},Pb:function(){return cP},L$:function(){return cL},cf:function(){return hW},sc:function(){return hQ},Xo:function(){return hp},IO:function(){return hu},iE:function(){return cn},Eo:function(){return ct},i3:function(){return h2},Bt:function(){return h3},pl:function(){return hz},Ub:function(){return nB},qK:function(){return hM},TQ:function(){return h_},e0:function(){return hw},r7:function(){return hG},Mx:function(){return cD},ar:function(){return hh}});var r,i,s,a,o,l,u,c,h=n(2238),d=n(8463),f=n(3333),p=n(4444),m="undefined"!=typeof globalThis?globalThis:"undefined"!=typeof window?window:void 0!==n.g?n.g:"undefined"!=typeof self?self:{},g={},y=y||{},v=m||self;function w(){}function _(e){var t=typeof e;return"array"==(t="object"!=t?t:e?Array.isArray(e)?"array":t:"null")||"object"==t&&"number"==typeof e.length}function b(e){var t=typeof e;return"object"==t&&null!=e||"function"==t}function I(e,t,n){return e.call.apply(e.bind,arguments)}function T(e,t,n){if(!e)throw Error();if(2<arguments.length){var r=Array.prototype.slice.call(arguments,2);return function(){var n=Array.prototype.slice.call(arguments);return Array.prototype.unshift.apply(n,r),e.apply(t,n)}}return function(){return e.apply(t,arguments)}}function E(e,t,n){return(E=Function.prototype.bind&&-1!=Function.prototype.bind.toString().indexOf("native code")?I:T).apply(null,arguments)}function S(e,t){var n=Array.prototype.slice.call(arguments,1);return function(){var t=n.slice();return t.push.apply(t,arguments),e.apply(this,t)}}function k(e,t){function n(){}n.prototype=t.prototype,e.X=t.prototype,e.prototype=new n,e.prototype.constructor=e,e.Wb=function(e,n,r){for(var i=Array(arguments.length-2),s=2;s<arguments.length;s++)i[s-2]=arguments[s];return t.prototype[n].apply(e,i)}}function A(){this.s=this.s,this.o=this.o}A.prototype.s=!1,A.prototype.na=function(){this.s||(this.s=!0,this.M())},A.prototype.M=function(){if(this.o)for(;this.o.length;)this.o.shift()()};let C=Array.prototype.indexOf?function(e,t){return Array.prototype.indexOf.call(e,t,void 0)}:function(e,t){if("string"==typeof e)return"string"!=typeof t||1!=t.length?-1:e.indexOf(t,0);for(let n=0;n<e.length;n++)if(n in e&&e[n]===t)return n;return -1};function x(e){let t=e.length;if(0<t){let n=Array(t);for(let r=0;r<t;r++)n[r]=e[r];return n}return[]}function R(e,t){for(let n=1;n<arguments.length;n++){let r=arguments[n];if(_(r)){let i=e.length||0,s=r.length||0;e.length=i+s;for(let a=0;a<s;a++)e[i+a]=r[a]}else e.push(r)}}function D(e,t){this.type=e,this.g=this.target=t,this.defaultPrevented=!1}D.prototype.h=function(){this.defaultPrevented=!0};var N=function(){if(!v.addEventListener||!Object.defineProperty)return!1;var e=!1,t=Object.defineProperty({},"passive",{get:function(){e=!0}});try{v.addEventListener("test",w,t),v.removeEventListener("test",w,t)}catch(n){}return e}();function O(e){return/^[\s\xa0]*$/.test(e)}var P=String.prototype.trim?function(e){return e.trim()}:function(e){return/^[\s\xa0]*([\s\S]*?)[\s\xa0]*$/.exec(e)[1]};function L(e,t){return e<t?-1:e>t?1:0}function M(){var e=v.navigator;return e&&(e=e.userAgent)?e:""}function F(e){return -1!=M().indexOf(e)}function U(e){return U[" "](e),e}U[" "]=w;var V=F("Opera"),q=F("Trident")||F("MSIE"),B=F("Edge"),j=B||q,$=F("Gecko")&&!(-1!=M().toLowerCase().indexOf("webkit")&&!F("Edge"))&&!(F("Trident")||F("MSIE"))&&!F("Edge"),z=-1!=M().toLowerCase().indexOf("webkit")&&!F("Edge");function G(){var e=v.document;return e?e.documentMode:void 0}e:{var K,H="",W=(K=M(),$?/rv:([^\);]+)(\)|;)/.exec(K):B?/Edge\/([\d\.]+)/.exec(K):q?/\b(?:MSIE|rv)[: ]([^\);]+)(\)|;)/.exec(K):z?/WebKit\/(\S+)/.exec(K):V?/(?:Version)[ \/]?(\S+)/.exec(K):void 0);if(W&&(H=W?W[1]:""),q){var Q=G();if(null!=Q&&Q>parseFloat(H)){i=String(Q);break e}}i=H}var Y={},X=v.document&&q&&(G()||parseInt(i,10))||void 0;function J(e,t){if(D.call(this,e?e.type:""),this.relatedTarget=this.g=this.target=null,this.button=this.screenY=this.screenX=this.clientY=this.clientX=0,this.key="",this.metaKey=this.shiftKey=this.altKey=this.ctrlKey=!1,this.state=null,this.pointerId=0,this.pointerType="",this.i=null,e){var n=this.type=e.type,r=e.changedTouches&&e.changedTouches.length?e.changedTouches[0]:null;if(this.target=e.target||e.srcElement,this.g=t,t=e.relatedTarget){if($){e:{try{U(t.nodeName);var i=!0;break e}catch(s){}i=!1}i||(t=null)}}else"mouseover"==n?t=e.fromElement:"mouseout"==n&&(t=e.toElement);this.relatedTarget=t,r?(this.clientX=void 0!==r.clientX?r.clientX:r.pageX,this.clientY=void 0!==r.clientY?r.clientY:r.pageY,this.screenX=r.screenX||0,this.screenY=r.screenY||0):(this.clientX=void 0!==e.clientX?e.clientX:e.pageX,this.clientY=void 0!==e.clientY?e.clientY:e.pageY,this.screenX=e.screenX||0,this.screenY=e.screenY||0),this.button=e.button,this.key=e.key||"",this.ctrlKey=e.ctrlKey,this.altKey=e.altKey,this.shiftKey=e.shiftKey,this.metaKey=e.metaKey,this.pointerId=e.pointerId||0,this.pointerType="string"==typeof e.pointerType?e.pointerType:Z[e.pointerType]||"",this.state=e.state,this.i=e,e.defaultPrevented&&J.X.h.call(this)}}k(J,D);var Z={2:"touch",3:"pen",4:"mouse"};J.prototype.h=function(){J.X.h.call(this);var e=this.i;e.preventDefault?e.preventDefault():e.returnValue=!1};var ee="closure_listenable_"+(1e6*Math.random()|0),et=0;function en(e,t,n,r,i){this.listener=e,this.proxy=null,this.src=t,this.type=n,this.capture=!!r,this.ha=i,this.key=++et,this.ba=this.ea=!1}function er(e){e.ba=!0,e.listener=null,e.proxy=null,e.src=null,e.ha=null}function ei(e,t,n){for(let r in e)t.call(n,e[r],r,e)}function es(e){let t={};for(let n in e)t[n]=e[n];return t}let ea="constructor hasOwnProperty isPrototypeOf propertyIsEnumerable toLocaleString toString valueOf".split(" ");function eo(e,t){let n,r;for(let i=1;i<arguments.length;i++){for(n in r=arguments[i])e[n]=r[n];for(let s=0;s<ea.length;s++)n=ea[s],Object.prototype.hasOwnProperty.call(r,n)&&(e[n]=r[n])}}function el(e){this.src=e,this.g={},this.h=0}function eu(e,t){var n=t.type;if(n in e.g){var r,i=e.g[n],s=C(i,t);(r=0<=s)&&Array.prototype.splice.call(i,s,1),r&&(er(t),0==e.g[n].length&&(delete e.g[n],e.h--))}}function ec(e,t,n,r){for(var i=0;i<e.length;++i){var s=e[i];if(!s.ba&&s.listener==t&&!!n==s.capture&&s.ha==r)return i}return -1}el.prototype.add=function(e,t,n,r,i){var s=e.toString();(e=this.g[s])||(e=this.g[s]=[],this.h++);var a=ec(e,t,r,i);return -1<a?(t=e[a],n||(t.ea=!1)):((t=new en(t,this.src,s,!!r,i)).ea=n,e.push(t)),t};var eh="closure_lm_"+(1e6*Math.random()|0),ed={};function ef(e,t,n,r,i,s){if(!t)throw Error("Invalid event type");var a=b(i)?!!i.capture:!!i,o=ey(e);if(o||(e[eh]=o=new el(e)),(n=o.add(t,n,r,a,s)).proxy)return n;if(r=function e(t){return eg.call(e.src,e.listener,t)},n.proxy=r,r.src=e,r.listener=n,e.addEventListener)N||(i=a),void 0===i&&(i=!1),e.addEventListener(t.toString(),r,i);else if(e.attachEvent)e.attachEvent(em(t.toString()),r);else if(e.addListener&&e.removeListener)e.addListener(r);else throw Error("addEventListener and attachEvent are unavailable.");return n}function ep(e){if("number"!=typeof e&&e&&!e.ba){var t=e.src;if(t&&t[ee])eu(t.i,e);else{var n=e.type,r=e.proxy;t.removeEventListener?t.removeEventListener(n,r,e.capture):t.detachEvent?t.detachEvent(em(n),r):t.addListener&&t.removeListener&&t.removeListener(r),(n=ey(t))?(eu(n,e),0==n.h&&(n.src=null,t[eh]=null)):er(e)}}}function em(e){return e in ed?ed[e]:ed[e]="on"+e}function eg(e,t){if(e.ba)e=!0;else{t=new J(t,this);var n=e.listener,r=e.ha||e.src;e.ea&&ep(e),e=n.call(r,t)}return e}function ey(e){return(e=e[eh])instanceof el?e:null}var ev="__closure_events_fn_"+(1e9*Math.random()>>>0);function ew(e){return"function"==typeof e?e:(e[ev]||(e[ev]=function(t){return e.handleEvent(t)}),e[ev])}function e_(){A.call(this),this.i=new el(this),this.P=this,this.I=null}function eb(e,t){var n,r=e.I;if(r)for(n=[];r;r=r.I)n.push(r);if(e=e.P,r=t.type||t,"string"==typeof t)t=new D(t,e);else if(t instanceof D)t.target=t.target||e;else{var i=t;eo(t=new D(r,e),i)}if(i=!0,n)for(var s=n.length-1;0<=s;s--){var a=t.g=n[s];i=eI(a,r,!0,t)&&i}if(i=eI(a=t.g=e,r,!0,t)&&i,i=eI(a,r,!1,t)&&i,n)for(s=0;s<n.length;s++)i=eI(a=t.g=n[s],r,!1,t)&&i}function eI(e,t,n,r){if(!(t=e.i.g[String(t)]))return!0;t=t.concat();for(var i=!0,s=0;s<t.length;++s){var a=t[s];if(a&&!a.ba&&a.capture==n){var o=a.listener,l=a.ha||a.src;a.ea&&eu(e.i,a),i=!1!==o.call(l,r)&&i}}return i&&!r.defaultPrevented}k(e_,A),e_.prototype[ee]=!0,e_.prototype.removeEventListener=function(e,t,n,r){!function e(t,n,r,i,s){if(Array.isArray(n))for(var a=0;a<n.length;a++)e(t,n[a],r,i,s);else(i=b(i)?!!i.capture:!!i,r=ew(r),t&&t[ee])?(t=t.i,(n=String(n).toString())in t.g&&-1<(r=ec(a=t.g[n],r,i,s))&&(er(a[r]),Array.prototype.splice.call(a,r,1),0==a.length&&(delete t.g[n],t.h--))):t&&(t=ey(t))&&(n=t.g[n.toString()],t=-1,n&&(t=ec(n,r,i,s)),(r=-1<t?n[t]:null)&&ep(r))}(this,e,t,n,r)},e_.prototype.M=function(){if(e_.X.M.call(this),this.i){var e,t=this.i;for(e in t.g){for(var n=t.g[e],r=0;r<n.length;r++)er(n[r]);delete t.g[e],t.h--}}this.I=null},e_.prototype.N=function(e,t,n,r){return this.i.add(String(e),t,!1,n,r)},e_.prototype.O=function(e,t,n,r){return this.i.add(String(e),t,!0,n,r)};var eT=v.JSON.stringify,eE=new class{constructor(e,t){this.i=e,this.j=t,this.h=0,this.g=null}get(){let e;return 0<this.h?(this.h--,e=this.g,this.g=e.next,e.next=null):e=this.i(),e}}(()=>new eS,e=>e.reset());class eS{constructor(){this.next=this.g=this.h=null}set(e,t){this.h=e,this.g=t,this.next=null}reset(){this.next=this.g=this.h=null}}function ek(e,t){var n;a||(n=v.Promise.resolve(void 0),a=function(){n.then(ex)}),eA||(a(),eA=!0),eC.add(e,t)}var eA=!1,eC=new class{constructor(){this.h=this.g=null}add(e,t){let n=eE.get();n.set(e,t),this.h?this.h.next=n:this.g=n,this.h=n}};function ex(){let e;for(;e=null,(n=eC).g&&(e=n.g,n.g=n.g.next,n.g||(n.h=null),e.next=null),r=e;){try{r.h.call(r.g)}catch(t){!function(e){v.setTimeout(()=>{throw e},0)}(t)}var n,r,i=eE;i.j(r),100>i.h&&(i.h++,r.next=i.g,i.g=r)}eA=!1}function eR(e,t){e_.call(this),this.h=e||1,this.g=t||v,this.j=E(this.lb,this),this.l=Date.now()}function eD(e){e.ca=!1,e.R&&(e.g.clearTimeout(e.R),e.R=null)}function eN(e,t,n){if("function"==typeof e)n&&(e=E(e,n));else if(e&&"function"==typeof e.handleEvent)e=E(e.handleEvent,e);else throw Error("Invalid listener argument");return 2147483647<Number(t)?-1:v.setTimeout(e,t||0)}k(eR,e_),(c=eR.prototype).ca=!1,c.R=null,c.lb=function(){if(this.ca){var e=Date.now()-this.l;0<e&&e<.8*this.h?this.R=this.g.setTimeout(this.j,this.h-e):(this.R&&(this.g.clearTimeout(this.R),this.R=null),eb(this,"tick"),this.ca&&(eD(this),this.start()))}},c.start=function(){this.ca=!0,this.R||(this.R=this.g.setTimeout(this.j,this.h),this.l=Date.now())},c.M=function(){eR.X.M.call(this),eD(this),delete this.g};class eO extends A{constructor(e,t){super(),this.m=e,this.j=t,this.h=null,this.i=!1,this.g=null}l(e){this.h=arguments,this.g?this.i=!0:function e(t){t.g=eN(()=>{t.g=null,t.i&&(t.i=!1,e(t))},t.j);let n=t.h;t.h=null,t.m.apply(null,n)}(this)}M(){super.M(),this.g&&(v.clearTimeout(this.g),this.g=null,this.i=!1,this.h=null)}}function eP(e){A.call(this),this.h=e,this.g={}}k(eP,A);var eL=[];function eM(e,t,n,r){Array.isArray(n)||(n&&(eL[0]=n.toString()),n=eL);for(var i=0;i<n.length;i++){var s=function e(t,n,r,i,s){if(i&&i.once)return function e(t,n,r,i,s){if(Array.isArray(n)){for(var a=0;a<n.length;a++)e(t,n[a],r,i,s);return null}return r=ew(r),t&&t[ee]?t.O(n,r,b(i)?!!i.capture:!!i,s):ef(t,n,r,!0,i,s)}(t,n,r,i,s);if(Array.isArray(n)){for(var a=0;a<n.length;a++)e(t,n[a],r,i,s);return null}return r=ew(r),t&&t[ee]?t.N(n,r,b(i)?!!i.capture:!!i,s):ef(t,n,r,!1,i,s)}(t,n[i],r||e.handleEvent,!1,e.h||e);if(!s)break;e.g[s.key]=s}}function eF(e){ei(e.g,function(e,t){this.g.hasOwnProperty(t)&&ep(e)},e),e.g={}}function eU(){this.g=!0}function eV(e,t,n,r){e.info(function(){return"XMLHTTP TEXT ("+t+"): "+function(e,t){if(!e.g)return t;if(!t)return null;try{var n=JSON.parse(t);if(n){for(e=0;e<n.length;e++)if(Array.isArray(n[e])){var r=n[e];if(!(2>r.length)){var i=r[1];if(Array.isArray(i)&&!(1>i.length)){var s=i[0];if("noop"!=s&&"stop"!=s&&"close"!=s)for(var a=1;a<i.length;a++)i[a]=""}}}}return eT(n)}catch(o){return t}}(e,n)+(r?" "+r:"")})}eP.prototype.M=function(){eP.X.M.call(this),eF(this)},eP.prototype.handleEvent=function(){throw Error("EventHandler.handleEvent not implemented")},eU.prototype.Aa=function(){this.g=!1},eU.prototype.info=function(){};var eq={},eB=null;function ej(){return eB=eB||new e_}function e$(e){D.call(this,eq.Pa,e)}function ez(e){let t=ej();eb(t,new e$(t))}function eG(e,t){D.call(this,eq.STAT_EVENT,e),this.stat=t}function eK(e){let t=ej();eb(t,new eG(t,e))}function eH(e,t){D.call(this,eq.Qa,e),this.size=t}function eW(e,t){if("function"!=typeof e)throw Error("Fn must not be null and must be a function");return v.setTimeout(function(){e()},t)}eq.Pa="serverreachability",k(e$,D),eq.STAT_EVENT="statevent",k(eG,D),eq.Qa="timingevent",k(eH,D);var eQ={NO_ERROR:0,mb:1,zb:2,yb:3,tb:4,xb:5,Ab:6,Ma:7,TIMEOUT:8,Db:9},eY={rb:"complete",Nb:"success",Na:"error",Ma:"abort",Fb:"ready",Gb:"readystatechange",TIMEOUT:"timeout",Bb:"incrementaldata",Eb:"progress",ub:"downloadprogress",Vb:"uploadprogress"};function eX(){}function eJ(e){return e.h||(e.h=e.i())}function eZ(){}eX.prototype.h=null;var e0={OPEN:"a",qb:"b",Na:"c",Cb:"d"};function e1(){D.call(this,"d")}function e2(){D.call(this,"c")}function e4(){}function e3(e,t,n,r){this.l=e,this.j=t,this.m=n,this.U=r||1,this.S=new eP(this),this.O=e5,e=j?125:void 0,this.T=new eR(e),this.H=null,this.i=!1,this.s=this.A=this.v=this.K=this.F=this.V=this.B=null,this.D=[],this.g=null,this.C=0,this.o=this.u=null,this.Y=-1,this.I=!1,this.N=0,this.L=null,this.$=this.J=this.Z=this.P=!1,this.h=new e6}function e6(){this.i=null,this.g="",this.h=!1}k(e1,D),k(e2,D),k(e4,eX),e4.prototype.g=function(){return new XMLHttpRequest},e4.prototype.i=function(){return{}},o=new e4;var e5=45e3,e9={},e8={};function e7(e,t,n){e.K=1,e.v=ty(td(t)),e.s=n,e.P=!0,te(e,null)}function te(e,t){e.F=Date.now(),tr(e),e.A=td(e.v);var n=e.A,r=e.U;Array.isArray(r)||(r=[String(r)]),tR(n.i,"t",r),e.C=0,n=e.l.H,e.h=new e6,e.g=nw(e.l,n?t:null,!e.s),0<e.N&&(e.L=new eO(E(e.La,e,e.g),e.N)),eM(e.S,e.g,"readystatechange",e.ib),t=e.H?es(e.H):{},e.s?(e.u||(e.u="POST"),t["Content-Type"]="application/x-www-form-urlencoded",e.g.da(e.A,e.u,e.s,t)):(e.u="GET",e.g.da(e.A,e.u,null,t)),ez(),function(e,t,n,r,i,s){e.info(function(){if(e.g){if(s)for(var a="",o=s.split("&"),l=0;l<o.length;l++){var u=o[l].split("=");if(1<u.length){var c=u[0];u=u[1];var h=c.split("_");a=2<=h.length&&"type"==h[1]?a+(c+"=")+u+"&":a+(c+"=redacted&")}}else a=null}else a=s;return"XMLHTTP REQ ("+r+") [attempt "+i+"]: "+t+"\n"+n+"\n"+a})}(e.j,e.u,e.A,e.m,e.U,e.s)}function tt(e){return!!e.g&&"GET"==e.u&&2!=e.K&&e.l.Da}function tn(e,t,n){let r=!0,i;for(;!e.I&&e.C<n.length;)if((i=function(e,t){var n=e.C,r=t.indexOf("\n",n);return -1==r?e8:isNaN(n=Number(t.substring(n,r)))?e9:(r+=1)+n>t.length?e8:(t=t.substr(r,n),e.C=r+n,t)}(e,n))==e8){4==t&&(e.o=4,eK(14),r=!1),eV(e.j,e.m,null,"[Incomplete Response]");break}else if(i==e9){e.o=4,eK(15),eV(e.j,e.m,n,"[Invalid Chunk]"),r=!1;break}else eV(e.j,e.m,i,null),tl(e,i);tt(e)&&i!=e8&&i!=e9&&(e.h.g="",e.C=0),4!=t||0!=n.length||e.h.h||(e.o=1,eK(16),r=!1),e.i=e.i&&r,r?0<n.length&&!e.$&&(e.$=!0,(t=e.l).g==e&&t.$&&!t.K&&(t.j.info("Great, no buffering proxy detected. Bytes received: "+n.length),nh(t),t.K=!0,eK(11))):(eV(e.j,e.m,n,"[Invalid Chunked Response]"),to(e),ta(e))}function tr(e){e.V=Date.now()+e.O,ti(e,e.O)}function ti(e,t){if(null!=e.B)throw Error("WatchDog timer not null");e.B=eW(E(e.gb,e),t)}function ts(e){e.B&&(v.clearTimeout(e.B),e.B=null)}function ta(e){0==e.l.G||e.I||np(e.l,e)}function to(e){ts(e);var t=e.L;t&&"function"==typeof t.na&&t.na(),e.L=null,eD(e.T),eF(e.S),e.g&&(t=e.g,e.g=null,t.abort(),t.na())}function tl(e,t){try{var n=e.l;if(0!=n.G&&(n.g==e||tF(n.h,e))){if(!e.J&&tF(n.h,e)&&3==n.G){try{var r=n.Fa.g.parse(t)}catch(i){r=null}if(Array.isArray(r)&&3==r.length){var s=r;if(0==s[0]){e:if(!n.u){if(n.g){if(n.g.F+3e3<e.F)nf(n),nr(n);else break e}nc(n),eK(18)}}else n.Ba=s[1],0<n.Ba-n.T&&37500>s[2]&&n.L&&0==n.A&&!n.v&&(n.v=eW(E(n.cb,n),6e3));if(1>=tM(n.h)&&n.ja){try{n.ja()}catch(a){}n.ja=void 0}}else ng(n,11)}else if((e.J||n.g==e)&&nf(n),!O(t))for(s=n.Fa.g.parse(t),t=0;t<s.length;t++){let o=s[t];if(n.T=o[0],o=o[1],2==n.G){if("c"==o[0]){n.I=o[1],n.ka=o[2];let l=o[3];null!=l&&(n.ma=l,n.j.info("VER="+n.ma));let u=o[4];null!=u&&(n.Ca=u,n.j.info("SVER="+n.Ca));let c=o[5];null!=c&&"number"==typeof c&&0<c&&(r=1.5*c,n.J=r,n.j.info("backChannelRequestTimeoutMs_="+r)),r=n;let h=e.g;if(h){let d=h.g?h.g.getResponseHeader("X-Client-Wire-Protocol"):null;if(d){var f=r.h;f.g||-1==d.indexOf("spdy")&&-1==d.indexOf("quic")&&-1==d.indexOf("h2")||(f.j=f.l,f.g=new Set,f.h&&(tU(f,f.h),f.h=null))}if(r.D){let p=h.g?h.g.getResponseHeader("X-HTTP-Session-Id"):null;p&&(r.za=p,tg(r.F,r.D,p))}}if(n.G=3,n.l&&n.l.xa(),n.$&&(n.P=Date.now()-e.F,n.j.info("Handshake RTT: "+n.P+"ms")),(r=n).sa=nv(r,r.H?r.ka:null,r.V),e.J){tV(r.h,e);var m=r.J;m&&e.setTimeout(m),e.B&&(ts(e),tr(e)),r.g=e}else nu(r);0<n.i.length&&ns(n)}else"stop"!=o[0]&&"close"!=o[0]||ng(n,7)}else 3==n.G&&("stop"==o[0]||"close"==o[0]?"stop"==o[0]?ng(n,7):nn(n):"noop"!=o[0]&&n.l&&n.l.wa(o),n.A=0)}}ez(4)}catch(g){}}function tu(e,t){if(e.forEach&&"function"==typeof e.forEach)e.forEach(t,void 0);else if(_(e)||"string"==typeof e)Array.prototype.forEach.call(e,t,void 0);else for(var n=function(e){if(e.oa&&"function"==typeof e.oa)return e.oa();if(!e.W||"function"!=typeof e.W){if("undefined"!=typeof Map&&e instanceof Map)return Array.from(e.keys());if(!("undefined"!=typeof Set&&e instanceof Set)){if(_(e)||"string"==typeof e){var t=[];e=e.length;for(var n=0;n<e;n++)t.push(n);return t}for(let r in t=[],n=0,e)t[n++]=r;return t}}}(e),r=function(e){if(e.W&&"function"==typeof e.W)return e.W();if("undefined"!=typeof Map&&e instanceof Map||"undefined"!=typeof Set&&e instanceof Set)return Array.from(e.values());if("string"==typeof e)return e.split("");if(_(e)){for(var t=[],n=e.length,r=0;r<n;r++)t.push(e[r]);return t}for(r in t=[],n=0,e)t[n++]=e[r];return t}(e),i=r.length,s=0;s<i;s++)t.call(void 0,r[s],n&&n[s],e)}(c=e3.prototype).setTimeout=function(e){this.O=e},c.ib=function(e){e=e.target;let t=this.L;t&&3==t5(e)?t.l():this.La(e)},c.La=function(e){try{if(e==this.g)e:{let t=t5(this.g);var n=this.g.Ea();let r=this.g.aa();if(!(3>t)&&(3!=t||j||this.g&&(this.h.h||this.g.fa()||t9(this.g)))){this.I||4!=t||7==n||(8==n||0>=r?ez(3):ez(2)),ts(this);var i=this.g.aa();this.Y=i;t:if(tt(this)){var s=t9(this.g);e="";var a=s.length,o=4==t5(this.g);if(!this.h.i){if("undefined"==typeof TextDecoder){to(this),ta(this);var l="";break t}this.h.i=new v.TextDecoder}for(n=0;n<a;n++)this.h.h=!0,e+=this.h.i.decode(s[n],{stream:o&&n==a-1});s.splice(0,a),this.h.g+=e,this.C=0,l=this.h.g}else l=this.g.fa();if(this.i=200==i,function(e,t,n,r,i,s,a){e.info(function(){return"XMLHTTP RESP ("+r+") [ attempt "+i+"]: "+t+"\n"+n+"\n"+s+" "+a})}(this.j,this.u,this.A,this.m,this.U,t,i),this.i){if(this.Z&&!this.J){t:{if(this.g){var u,c=this.g;if((u=c.g?c.g.getResponseHeader("X-HTTP-Initial-Response"):null)&&!O(u)){var h=u;break t}}h=null}if(i=h)eV(this.j,this.m,i,"Initial handshake response via X-HTTP-Initial-Response"),this.J=!0,tl(this,i);else{this.i=!1,this.o=3,eK(12),to(this),ta(this);break e}}this.P?(tn(this,t,l),j&&this.i&&3==t&&(eM(this.S,this.T,"tick",this.hb),this.T.start())):(eV(this.j,this.m,l,null),tl(this,l)),4==t&&to(this),this.i&&!this.I&&(4==t?np(this.l,this):(this.i=!1,tr(this)))}else 400==i&&0<l.indexOf("Unknown SID")?(this.o=3,eK(12)):(this.o=0,eK(13)),to(this),ta(this)}}}catch(d){}finally{}},c.hb=function(){if(this.g){var e=t5(this.g),t=this.g.fa();this.C<t.length&&(ts(this),tn(this,e,t),this.i&&4!=e&&tr(this))}},c.cancel=function(){this.I=!0,to(this)},c.gb=function(){this.B=null;let e=Date.now();0<=e-this.V?(function(e,t){e.info(function(){return"TIMEOUT: "+t})}(this.j,this.A),2!=this.K&&(ez(),eK(17)),to(this),this.o=2,ta(this)):ti(this,this.V-e)};var tc=RegExp("^(?:([^:/?#.]+):)?(?://(?:([^\\\\/?#]*)@)?([^\\\\/?#]*?)(?::([0-9]+))?(?=[\\\\/?#]|$))?([^?#]+)?(?:\\?([^#]*))?(?:#([\\s\\S]*))?$");function th(e,t){if(this.g=this.s=this.j="",this.m=null,this.o=this.l="",this.h=!1,e instanceof th){this.h=void 0!==t?t:e.h,tf(this,e.j),this.s=e.s,this.g=e.g,tp(this,e.m),this.l=e.l,t=e.i;var n=new tk;n.i=t.i,t.g&&(n.g=new Map(t.g),n.h=t.h),tm(this,n),this.o=e.o}else e&&(n=String(e).match(tc))?(this.h=!!t,tf(this,n[1]||"",!0),this.s=tv(n[2]||""),this.g=tv(n[3]||"",!0),tp(this,n[4]),this.l=tv(n[5]||"",!0),tm(this,n[6]||"",!0),this.o=tv(n[7]||"")):(this.h=!!t,this.i=new tk(null,this.h))}function td(e){return new th(e)}function tf(e,t,n){e.j=n?tv(t,!0):t,e.j&&(e.j=e.j.replace(/:$/,""))}function tp(e,t){if(t){if(isNaN(t=Number(t))||0>t)throw Error("Bad port number "+t);e.m=t}else e.m=null}function tm(e,t,n){var r,i;t instanceof tk?(e.i=t,r=e.i,(i=e.h)&&!r.j&&(tA(r),r.i=null,r.g.forEach(function(e,t){var n=t.toLowerCase();t!=n&&(tC(this,t),tR(this,n,e))},r)),r.j=i):(n||(t=tw(t,tE)),e.i=new tk(t,e.h))}function tg(e,t,n){e.i.set(t,n)}function ty(e){return tg(e,"zx",Math.floor(2147483648*Math.random()).toString(36)+Math.abs(Math.floor(2147483648*Math.random())^Date.now()).toString(36)),e}function tv(e,t){return e?t?decodeURI(e.replace(/%25/g,"%2525")):decodeURIComponent(e):""}function tw(e,t,n){return"string"==typeof e?(e=encodeURI(e).replace(t,t_),n&&(e=e.replace(/%25([0-9a-fA-F]{2})/g,"%$1")),e):null}function t_(e){return"%"+((e=e.charCodeAt(0))>>4&15).toString(16)+(15&e).toString(16)}th.prototype.toString=function(){var e=[],t=this.j;t&&e.push(tw(t,tb,!0),":");var n=this.g;return(n||"file"==t)&&(e.push("//"),(t=this.s)&&e.push(tw(t,tb,!0),"@"),e.push(encodeURIComponent(String(n)).replace(/%25([0-9a-fA-F]{2})/g,"%$1")),null!=(n=this.m)&&e.push(":",String(n))),(n=this.l)&&(this.g&&"/"!=n.charAt(0)&&e.push("/"),e.push(tw(n,"/"==n.charAt(0)?tT:tI,!0))),(n=this.i.toString())&&e.push("?",n),(n=this.o)&&e.push("#",tw(n,tS)),e.join("")};var tb=/[#\/\?@]/g,tI=/[#\?:]/g,tT=/[#\?]/g,tE=/[#\?@]/g,tS=/#/g;function tk(e,t){this.h=this.g=null,this.i=e||null,this.j=!!t}function tA(e){e.g||(e.g=new Map,e.h=0,e.i&&function(e,t){if(e){e=e.split("&");for(var n=0;n<e.length;n++){var r=e[n].indexOf("="),i=null;if(0<=r){var s=e[n].substring(0,r);i=e[n].substring(r+1)}else s=e[n];t(s,i?decodeURIComponent(i.replace(/\+/g," ")):"")}}}(e.i,function(t,n){e.add(decodeURIComponent(t.replace(/\+/g," ")),n)}))}function tC(e,t){tA(e),t=tD(e,t),e.g.has(t)&&(e.i=null,e.h-=e.g.get(t).length,e.g.delete(t))}function tx(e,t){return tA(e),t=tD(e,t),e.g.has(t)}function tR(e,t,n){tC(e,t),0<n.length&&(e.i=null,e.g.set(tD(e,t),x(n)),e.h+=n.length)}function tD(e,t){return t=String(t),e.j&&(t=t.toLowerCase()),t}(c=tk.prototype).add=function(e,t){tA(this),this.i=null,e=tD(this,e);var n=this.g.get(e);return n||this.g.set(e,n=[]),n.push(t),this.h+=1,this},c.forEach=function(e,t){tA(this),this.g.forEach(function(n,r){n.forEach(function(n){e.call(t,n,r,this)},this)},this)},c.oa=function(){tA(this);let e=Array.from(this.g.values()),t=Array.from(this.g.keys()),n=[];for(let r=0;r<t.length;r++){let i=e[r];for(let s=0;s<i.length;s++)n.push(t[r])}return n},c.W=function(e){tA(this);let t=[];if("string"==typeof e)tx(this,e)&&(t=t.concat(this.g.get(tD(this,e))));else{e=Array.from(this.g.values());for(let n=0;n<e.length;n++)t=t.concat(e[n])}return t},c.set=function(e,t){return tA(this),this.i=null,tx(this,e=tD(this,e))&&(this.h-=this.g.get(e).length),this.g.set(e,[t]),this.h+=1,this},c.get=function(e,t){return e&&0<(e=this.W(e)).length?String(e[0]):t},c.toString=function(){if(this.i)return this.i;if(!this.g)return"";let e=[],t=Array.from(this.g.keys());for(var n=0;n<t.length;n++){var r=t[n];let i=encodeURIComponent(String(r)),s=this.W(r);for(r=0;r<s.length;r++){var a=i;""!==s[r]&&(a+="="+encodeURIComponent(String(s[r]))),e.push(a)}}return this.i=e.join("&")};var tN=class{constructor(e,t){this.h=e,this.g=t}};function tO(e){this.l=e||tP,e=v.PerformanceNavigationTiming?0<(e=v.performance.getEntriesByType("navigation")).length&&("hq"==e[0].nextHopProtocol||"h2"==e[0].nextHopProtocol):!!(v.g&&v.g.Ga&&v.g.Ga()&&v.g.Ga().$b),this.j=e?this.l:1,this.g=null,1<this.j&&(this.g=new Set),this.h=null,this.i=[]}var tP=10;function tL(e){return!!e.h||!!e.g&&e.g.size>=e.j}function tM(e){return e.h?1:e.g?e.g.size:0}function tF(e,t){return e.h?e.h==t:!!e.g&&e.g.has(t)}function tU(e,t){e.g?e.g.add(t):e.h=t}function tV(e,t){e.h&&e.h==t?e.h=null:e.g&&e.g.has(t)&&e.g.delete(t)}function tq(e){if(null!=e.h)return e.i.concat(e.h.D);if(null!=e.g&&0!==e.g.size){let t=e.i;for(let n of e.g.values())t=t.concat(n.D);return t}return x(e.i)}function tB(){}function tj(){this.g=new tB}function t$(e,t,n,r,i){try{t.onload=null,t.onerror=null,t.onabort=null,t.ontimeout=null,i(r)}catch(s){}}function tz(e){this.l=e.ac||null,this.j=e.jb||!1}function tG(e,t){e_.call(this),this.D=e,this.u=t,this.m=void 0,this.readyState=tK,this.status=0,this.responseType=this.responseText=this.response=this.statusText="",this.onreadystatechange=null,this.v=new Headers,this.h=null,this.C="GET",this.B="",this.g=!1,this.A=this.j=this.l=null}tO.prototype.cancel=function(){if(this.i=tq(this),this.h)this.h.cancel(),this.h=null;else if(this.g&&0!==this.g.size){for(let e of this.g.values())e.cancel();this.g.clear()}},tB.prototype.stringify=function(e){return v.JSON.stringify(e,void 0)},tB.prototype.parse=function(e){return v.JSON.parse(e,void 0)},k(tz,eX),tz.prototype.g=function(){return new tG(this.l,this.j)},tz.prototype.i=(r={},function(){return r}),k(tG,e_);var tK=0;function tH(e){e.j.read().then(e.Ta.bind(e)).catch(e.ga.bind(e))}function tW(e){e.readyState=4,e.l=null,e.j=null,e.A=null,tQ(e)}function tQ(e){e.onreadystatechange&&e.onreadystatechange.call(e)}(c=tG.prototype).open=function(e,t){if(this.readyState!=tK)throw this.abort(),Error("Error reopening a connection");this.C=e,this.B=t,this.readyState=1,tQ(this)},c.send=function(e){if(1!=this.readyState)throw this.abort(),Error("need to call open() first. ");this.g=!0;let t={headers:this.v,method:this.C,credentials:this.m,cache:void 0};e&&(t.body=e),(this.D||v).fetch(new Request(this.B,t)).then(this.Wa.bind(this),this.ga.bind(this))},c.abort=function(){this.response=this.responseText="",this.v=new Headers,this.status=0,this.j&&this.j.cancel("Request was aborted.").catch(()=>{}),1<=this.readyState&&this.g&&4!=this.readyState&&(this.g=!1,tW(this)),this.readyState=tK},c.Wa=function(e){if(this.g&&(this.l=e,this.h||(this.status=this.l.status,this.statusText=this.l.statusText,this.h=e.headers,this.readyState=2,tQ(this)),this.g&&(this.readyState=3,tQ(this),this.g))){if("arraybuffer"===this.responseType)e.arrayBuffer().then(this.Ua.bind(this),this.ga.bind(this));else if(void 0!==v.ReadableStream&&"body"in e){if(this.j=e.body.getReader(),this.u){if(this.responseType)throw Error('responseType must be empty for "streamBinaryChunks" mode responses.');this.response=[]}else this.response=this.responseText="",this.A=new TextDecoder;tH(this)}else e.text().then(this.Va.bind(this),this.ga.bind(this))}},c.Ta=function(e){if(this.g){if(this.u&&e.value)this.response.push(e.value);else if(!this.u){var t=e.value?e.value:new Uint8Array(0);(t=this.A.decode(t,{stream:!e.done}))&&(this.response=this.responseText+=t)}e.done?tW(this):tQ(this),3==this.readyState&&tH(this)}},c.Va=function(e){this.g&&(this.response=this.responseText=e,tW(this))},c.Ua=function(e){this.g&&(this.response=e,tW(this))},c.ga=function(){this.g&&tW(this)},c.setRequestHeader=function(e,t){this.v.append(e,t)},c.getResponseHeader=function(e){return this.h&&this.h.get(e.toLowerCase())||""},c.getAllResponseHeaders=function(){if(!this.h)return"";let e=[],t=this.h.entries();for(var n=t.next();!n.done;)e.push((n=n.value)[0]+": "+n[1]),n=t.next();return e.join("\r\n")},Object.defineProperty(tG.prototype,"withCredentials",{get:function(){return"include"===this.m},set:function(e){this.m=e?"include":"same-origin"}});var tY=v.JSON.parse;function tX(e){e_.call(this),this.headers=new Map,this.u=e||null,this.h=!1,this.C=this.g=null,this.H="",this.m=0,this.j="",this.l=this.F=this.v=this.D=!1,this.B=0,this.A=null,this.J=tJ,this.K=this.L=!1}k(tX,e_);var tJ="",tZ=/^https?$/i,t0=["POST","PUT"];function t1(e,t){e.h=!1,e.g&&(e.l=!0,e.g.abort(),e.l=!1),e.j=t,e.m=5,t2(e),t3(e)}function t2(e){e.D||(e.D=!0,eb(e,"complete"),eb(e,"error"))}function t4(e){if(e.h&&void 0!==y&&(!e.C[1]||4!=t5(e)||2!=e.aa())){if(e.v&&4==t5(e))eN(e.Ha,0,e);else if(eb(e,"readystatechange"),4==t5(e)){e.h=!1;try{let t=e.aa();e:switch(t){case 200:case 201:case 202:case 204:case 206:case 304:case 1223:var n,r,i=!0;break e;default:i=!1}if(!(n=i)){if(r=0===t){var s=String(e.H).match(tc)[1]||null;if(!s&&v.self&&v.self.location){var a=v.self.location.protocol;s=a.substr(0,a.length-1)}r=!tZ.test(s?s.toLowerCase():"")}n=r}if(n)eb(e,"complete"),eb(e,"success");else{e.m=6;try{var o=2<t5(e)?e.g.statusText:""}catch(l){o=""}e.j=o+" ["+e.aa()+"]",t2(e)}}finally{t3(e)}}}}function t3(e,t){if(e.g){t6(e);let n=e.g,r=e.C[0]?w:null;e.g=null,e.C=null,t||eb(e,"ready");try{n.onreadystatechange=r}catch(i){}}}function t6(e){e.g&&e.K&&(e.g.ontimeout=null),e.A&&(v.clearTimeout(e.A),e.A=null)}function t5(e){return e.g?e.g.readyState:0}function t9(e){try{if(!e.g)return null;if("response"in e.g)return e.g.response;switch(e.J){case tJ:case"text":return e.g.responseText;case"arraybuffer":if("mozResponseArrayBuffer"in e.g)return e.g.mozResponseArrayBuffer}return null}catch(t){return null}}function t8(e){let t="";return ei(e,function(e,n){t+=n+":"+e+"\r\n"}),t}function t7(e,t,n){e:{for(r in n){var r=!1;break e}r=!0}r||(n=t8(n),"string"==typeof e?null!=n&&encodeURIComponent(String(n)):tg(e,t,n))}function ne(e,t,n){return n&&n.internalChannelParams&&n.internalChannelParams[e]||t}function nt(e){this.Ca=0,this.i=[],this.j=new eU,this.ka=this.sa=this.F=this.V=this.g=this.za=this.D=this.ia=this.o=this.S=this.s=null,this.ab=this.U=0,this.Za=ne("failFast",!1,e),this.L=this.v=this.u=this.m=this.l=null,this.Y=!0,this.pa=this.Ba=this.T=-1,this.Z=this.A=this.C=0,this.Xa=ne("baseRetryDelayMs",5e3,e),this.bb=ne("retryDelaySeedMs",1e4,e),this.$a=ne("forwardChannelMaxRetries",2,e),this.ta=ne("forwardChannelRequestTimeoutMs",2e4,e),this.ra=e&&e.xmlHttpFactory||void 0,this.Da=e&&e.Zb||!1,this.J=void 0,this.H=e&&e.supportsCrossDomainXhr||!1,this.I="",this.h=new tO(e&&e.concurrentRequestLimit),this.Fa=new tj,this.O=e&&e.fastHandshake||!1,this.N=e&&e.encodeInitMessageHeaders||!1,this.O&&this.N&&(this.N=!1),this.Ya=e&&e.Xb||!1,e&&e.Aa&&this.j.Aa(),e&&e.forceLongPolling&&(this.Y=!1),this.$=!this.O&&this.Y&&e&&e.detectBufferingProxy||!1,this.ja=void 0,this.P=0,this.K=!1,this.la=this.B=null}function nn(e){if(ni(e),3==e.G){var t=e.U++,n=td(e.F);tg(n,"SID",e.I),tg(n,"RID",t),tg(n,"TYPE","terminate"),no(e,n),(t=new e3(e,e.j,t,void 0)).K=2,t.v=ty(td(n)),n=!1,v.navigator&&v.navigator.sendBeacon&&(n=v.navigator.sendBeacon(t.v.toString(),"")),!n&&v.Image&&((new Image).src=t.v,n=!0),n||(t.g=nw(t.l,null),t.g.da(t.v)),t.F=Date.now(),tr(t)}ny(e)}function nr(e){e.g&&(nh(e),e.g.cancel(),e.g=null)}function ni(e){nr(e),e.u&&(v.clearTimeout(e.u),e.u=null),nf(e),e.h.cancel(),e.m&&("number"==typeof e.m&&v.clearTimeout(e.m),e.m=null)}function ns(e){tL(e.h)||e.m||(e.m=!0,ek(e.Ja,e),e.C=0)}function na(e,t){var n;n=t?t.m:e.U++;let r=td(e.F);tg(r,"SID",e.I),tg(r,"RID",n),tg(r,"AID",e.T),no(e,r),e.o&&e.s&&t7(r,e.o,e.s),n=new e3(e,e.j,n,e.C+1),null===e.o&&(n.H=e.s),t&&(e.i=t.D.concat(e.i)),t=nl(e,n,1e3),n.setTimeout(Math.round(.5*e.ta)+Math.round(.5*e.ta*Math.random())),tU(e.h,n),e7(n,r,t)}function no(e,t){e.ia&&ei(e.ia,function(e,n){tg(t,n,e)}),e.l&&tu({},function(e,n){tg(t,n,e)})}function nl(e,t,n){n=Math.min(e.i.length,n);var r=e.l?E(e.l.Ra,e.l,e):null;e:{var i=e.i;let s=-1;for(;;){let a=["count="+n];-1==s?0<n?(s=i[0].h,a.push("ofs="+s)):s=0:a.push("ofs="+s);let o=!0;for(let l=0;l<n;l++){let u=i[l].h,c=i[l].g;if(0>(u-=s))s=Math.max(0,i[l].h-100),o=!1;else try{!function(e,t,n){let r=n||"";try{tu(e,function(e,n){let i=e;b(e)&&(i=eT(e)),t.push(r+n+"="+encodeURIComponent(i))})}catch(i){throw t.push(r+"type="+encodeURIComponent("_badmap")),i}}(c,a,"req"+u+"_")}catch(h){r&&r(c)}}if(o){r=a.join("&");break e}}}return e=e.i.splice(0,n),t.D=e,r}function nu(e){e.g||e.u||(e.Z=1,ek(e.Ia,e),e.A=0)}function nc(e){return!e.g&&!e.u&&!(3<=e.A)&&(e.Z++,e.u=eW(E(e.Ia,e),nm(e,e.A)),e.A++,!0)}function nh(e){null!=e.B&&(v.clearTimeout(e.B),e.B=null)}function nd(e){e.g=new e3(e,e.j,"rpc",e.Z),null===e.o&&(e.g.H=e.s),e.g.N=0;var t=td(e.sa);tg(t,"RID","rpc"),tg(t,"SID",e.I),tg(t,"CI",e.L?"0":"1"),tg(t,"AID",e.T),tg(t,"TYPE","xmlhttp"),no(e,t),e.o&&e.s&&t7(t,e.o,e.s),e.J&&e.g.setTimeout(e.J);var n=e.g;e=e.ka,n.K=1,n.v=ty(td(t)),n.s=null,n.P=!0,te(n,e)}function nf(e){null!=e.v&&(v.clearTimeout(e.v),e.v=null)}function np(e,t){var n=null;if(e.g==t){nf(e),nh(e),e.g=null;var r=2}else{if(!tF(e.h,t))return;n=t.D,tV(e.h,t),r=1}if(0!=e.G){if(e.pa=t.Y,t.i){if(1==r){n=t.s?t.s.length:0,t=Date.now()-t.F;var i,s,a=e.C;eb(r=ej(),new eH(r,n)),ns(e)}else nu(e)}else if(3==(a=t.o)||0==a&&0<e.pa||!(1==r&&(i=e,s=t,!(tM(i.h)>=i.h.j-(i.m?1:0))&&(i.m?(i.i=s.D.concat(i.i),!0):1!=i.G&&2!=i.G&&!(i.C>=(i.Za?0:i.$a))&&(i.m=eW(E(i.Ja,i,s),nm(i,i.C)),i.C++,!0)))||2==r&&nc(e)))switch(n&&0<n.length&&((t=e.h).i=t.i.concat(n)),a){case 1:ng(e,5);break;case 4:ng(e,10);break;case 3:ng(e,6);break;default:ng(e,2)}}}function nm(e,t){let n=e.Xa+Math.floor(Math.random()*e.bb);return e.l||(n*=2),n*t}function ng(e,t){if(e.j.info("Error code "+t),2==t){var n=null;e.l&&(n=null);var r=E(e.kb,e);n||(n=new th("//www.google.com/images/cleardot.gif"),v.location&&"http"==v.location.protocol||tf(n,"https"),ty(n)),function(e,t){let n=new eU;if(v.Image){let r=new Image;r.onload=S(t$,n,r,"TestLoadImage: loaded",!0,t),r.onerror=S(t$,n,r,"TestLoadImage: error",!1,t),r.onabort=S(t$,n,r,"TestLoadImage: abort",!1,t),r.ontimeout=S(t$,n,r,"TestLoadImage: timeout",!1,t),v.setTimeout(function(){r.ontimeout&&r.ontimeout()},1e4),r.src=e}else t(!1)}(n.toString(),r)}else eK(2);e.G=0,e.l&&e.l.va(t),ny(e),ni(e)}function ny(e){if(e.G=0,e.la=[],e.l){let t=tq(e.h);(0!=t.length||0!=e.i.length)&&(R(e.la,t),R(e.la,e.i),e.h.i.length=0,x(e.i),e.i.length=0),e.l.ua()}}function nv(e,t,n){var r=n instanceof th?td(n):new th(n,void 0);if(""!=r.g)t&&(r.g=t+"."+r.g),tp(r,r.m);else{var i=v.location;r=i.protocol,t=t?t+"."+i.hostname:i.hostname,i=+i.port;var s=new th(null,void 0);r&&tf(s,r),t&&(s.g=t),i&&tp(s,i),n&&(s.l=n),r=s}return n=e.D,t=e.za,n&&t&&tg(r,n,t),tg(r,"VER",e.ma),no(e,r),r}function nw(e,t,n){if(t&&!e.H)throw Error("Can't create secondary domain capable XhrIo object.");return(t=new tX(n&&e.Da&&!e.ra?new tz({jb:!0}):e.ra)).Ka(e.H),t}function n_(){}function nb(){if(q&&!(10<=Number(X)))throw Error("Environmental error: no available transport.")}function nI(e,t){e_.call(this),this.g=new nt(t),this.l=e,this.h=t&&t.messageUrlParams||null,e=t&&t.messageHeaders||null,t&&t.clientProtocolHeaderRequired&&(e?e["X-Client-Protocol"]="webchannel":e={"X-Client-Protocol":"webchannel"}),this.g.s=e,e=t&&t.initMessageHeaders||null,t&&t.messageContentType&&(e?e["X-WebChannel-Content-Type"]=t.messageContentType:e={"X-WebChannel-Content-Type":t.messageContentType}),t&&t.ya&&(e?e["X-WebChannel-Client-Profile"]=t.ya:e={"X-WebChannel-Client-Profile":t.ya}),this.g.S=e,(e=t&&t.Yb)&&!O(e)&&(this.g.o=e),this.A=t&&t.supportsCrossDomainXhr||!1,this.v=t&&t.sendRawJson||!1,(t=t&&t.httpSessionIdParam)&&!O(t)&&(this.g.D=t,null!==(e=this.h)&&t in e&&t in(e=this.h)&&delete e[t]),this.j=new nS(this)}function nT(e){e1.call(this);var t=e.__sm__;if(t){e:{for(let n in t){e=n;break e}e=void 0}(this.i=e)&&(e=this.i,t=null!==t&&e in t?t[e]:void 0),this.data=t}else this.data=e}function nE(){e2.call(this),this.status=1}function nS(e){this.g=e}(c=tX.prototype).Ka=function(e){this.L=e},c.da=function(e,t,n,r){if(this.g)throw Error("[goog.net.XhrIo] Object is active with another request="+this.H+"; newUri="+e);t=t?t.toUpperCase():"GET",this.H=e,this.j="",this.m=0,this.D=!1,this.h=!0,this.g=this.u?this.u.g():o.g(),this.C=this.u?eJ(this.u):eJ(o),this.g.onreadystatechange=E(this.Ha,this);try{this.F=!0,this.g.open(t,String(e),!0),this.F=!1}catch(s){t1(this,s);return}if(e=n||"",n=new Map(this.headers),r){if(Object.getPrototypeOf(r)===Object.prototype)for(var a in r)n.set(a,r[a]);else if("function"==typeof r.keys&&"function"==typeof r.get)for(let l of r.keys())n.set(l,r.get(l));else throw Error("Unknown input type for opt_headers: "+String(r))}for(let[u,c]of(r=Array.from(n.keys()).find(e=>"content-type"==e.toLowerCase()),a=v.FormData&&e instanceof v.FormData,!(0<=C(t0,t))||r||a||n.set("Content-Type","application/x-www-form-urlencoded;charset=utf-8"),n))this.g.setRequestHeader(u,c);this.J&&(this.g.responseType=this.J),"withCredentials"in this.g&&this.g.withCredentials!==this.L&&(this.g.withCredentials=this.L);try{var h,d;t6(this),0<this.B&&((this.K=(h=this.g,q&&(d=Y,Object.prototype.hasOwnProperty.call(d,9)?d[9]:d[9]=function(){let e=0,t=P(String(i)).split("."),n=P("9").split("."),r=Math.max(t.length,n.length);for(let s=0;0==e&&s<r;s++){var a=t[s]||"",o=n[s]||"";do{if(a=/(\d*)(\D*)(.*)/.exec(a)||["","","",""],o=/(\d*)(\D*)(.*)/.exec(o)||["","","",""],0==a[0].length&&0==o[0].length)break;e=L(0==a[1].length?0:parseInt(a[1],10),0==o[1].length?0:parseInt(o[1],10))||L(0==a[2].length,0==o[2].length)||L(a[2],o[2]),a=a[3],o=o[3]}while(0==e)}return 0<=e}(9))&&"number"==typeof h.timeout&&void 0!==h.ontimeout))?(this.g.timeout=this.B,this.g.ontimeout=E(this.qa,this)):this.A=eN(this.qa,this.B,this)),this.v=!0,this.g.send(e),this.v=!1}catch(f){t1(this,f)}},c.qa=function(){void 0!==y&&this.g&&(this.j="Timed out after "+this.B+"ms, aborting",this.m=8,eb(this,"timeout"),this.abort(8))},c.abort=function(e){this.g&&this.h&&(this.h=!1,this.l=!0,this.g.abort(),this.l=!1,this.m=e||7,eb(this,"complete"),eb(this,"abort"),t3(this))},c.M=function(){this.g&&(this.h&&(this.h=!1,this.l=!0,this.g.abort(),this.l=!1),t3(this,!0)),tX.X.M.call(this)},c.Ha=function(){this.s||(this.F||this.v||this.l?t4(this):this.fb())},c.fb=function(){t4(this)},c.aa=function(){try{return 2<t5(this)?this.g.status:-1}catch(e){return -1}},c.fa=function(){try{return this.g?this.g.responseText:""}catch(e){return""}},c.Sa=function(e){if(this.g){var t=this.g.responseText;return e&&0==t.indexOf(e)&&(t=t.substring(e.length)),tY(t)}},c.Ea=function(){return this.m},c.Oa=function(){return"string"==typeof this.j?this.j:String(this.j)},(c=nt.prototype).ma=8,c.G=1,c.Ja=function(e){if(this.m){if(this.m=null,1==this.G){if(!e){this.U=Math.floor(1e5*Math.random()),e=this.U++;let t=new e3(this,this.j,e,void 0),n=this.s;if(this.S&&(n?eo(n=es(n),this.S):n=this.S),null!==this.o||this.N||(t.H=n,n=null),this.O)e:{for(var r=0,i=0;i<this.i.length;i++){t:{var s=this.i[i];if("__data__"in s.g&&"string"==typeof(s=s.g.__data__)){s=s.length;break t}s=void 0}if(void 0===s)break;if(4096<(r+=s)){r=i;break e}if(4096===r||i===this.i.length-1){r=i+1;break e}}r=1e3}else r=1e3;r=nl(this,t,r),tg(i=td(this.F),"RID",e),tg(i,"CVER",22),this.D&&tg(i,"X-HTTP-Session-Id",this.D),no(this,i),n&&(this.N?r="headers="+encodeURIComponent(String(t8(n)))+"&"+r:this.o&&t7(i,this.o,n)),tU(this.h,t),this.Ya&&tg(i,"TYPE","init"),this.O?(tg(i,"$req",r),tg(i,"SID","null"),t.Z=!0,e7(t,i,null)):e7(t,i,r),this.G=2}}else 3==this.G&&(e?na(this,e):0==this.i.length||tL(this.h)||na(this))}},c.Ia=function(){if(this.u=null,nd(this),this.$&&!(this.K||null==this.g||0>=this.P)){var e=2*this.P;this.j.info("BP detection timer enabled: "+e),this.B=eW(E(this.eb,this),e)}},c.eb=function(){this.B&&(this.B=null,this.j.info("BP detection timeout reached."),this.j.info("Buffering proxy detected and switch to long-polling!"),this.L=!1,this.K=!0,eK(10),nr(this),nd(this))},c.cb=function(){null!=this.v&&(this.v=null,nr(this),nc(this),eK(19))},c.kb=function(e){e?(this.j.info("Successfully pinged google.com"),eK(2)):(this.j.info("Failed to ping google.com"),eK(1))},(c=n_.prototype).xa=function(){},c.wa=function(){},c.va=function(){},c.ua=function(){},c.Ra=function(){},nb.prototype.g=function(e,t){return new nI(e,t)},k(nI,e_),nI.prototype.m=function(){this.g.l=this.j,this.A&&(this.g.H=!0);var e=this.g,t=this.l,n=this.h||void 0;eK(0),e.V=t,e.ia=n||{},e.L=e.Y,e.F=nv(e,null,e.V),ns(e)},nI.prototype.close=function(){nn(this.g)},nI.prototype.u=function(e){var t=this.g;if("string"==typeof e){var n={};n.__data__=e,e=n}else this.v&&((n={}).__data__=eT(e),e=n);t.i.push(new tN(t.ab++,e)),3==t.G&&ns(t)},nI.prototype.M=function(){this.g.l=null,delete this.j,nn(this.g),delete this.g,nI.X.M.call(this)},k(nT,e1),k(nE,e2),k(nS,n_),nS.prototype.xa=function(){eb(this.g,"a")},nS.prototype.wa=function(e){eb(this.g,new nT(e))},nS.prototype.va=function(e){eb(this.g,new nE)},nS.prototype.ua=function(){eb(this.g,"b")},nb.prototype.createWebChannel=nb.prototype.g,nI.prototype.send=nI.prototype.u,nI.prototype.open=nI.prototype.m,nI.prototype.close=nI.prototype.close,eQ.NO_ERROR=0,eQ.TIMEOUT=8,eQ.HTTP_ERROR=6,eY.COMPLETE="complete",eZ.EventType=e0,e0.OPEN="a",e0.CLOSE="b",e0.ERROR="c",e0.MESSAGE="d",e_.prototype.listen=e_.prototype.N,tX.prototype.listenOnce=tX.prototype.O,tX.prototype.getLastError=tX.prototype.Oa,tX.prototype.getLastErrorCode=tX.prototype.Ea,tX.prototype.getStatus=tX.prototype.aa,tX.prototype.getResponseJson=tX.prototype.Sa,tX.prototype.getResponseText=tX.prototype.fa,tX.prototype.send=tX.prototype.da,tX.prototype.setWithCredentials=tX.prototype.Ka;var nk=g.createWebChannelTransport=function(){return new nb},nA=g.getStatEventTarget=function(){return ej()},nC=g.ErrorCode=eQ,nx=g.EventType=eY,nR=g.Event=eq,nD=g.Stat={sb:0,vb:1,wb:2,Pb:3,Ub:4,Rb:5,Sb:6,Qb:7,Ob:8,Tb:9,PROXY:10,NOPROXY:11,Mb:12,Ib:13,Jb:14,Hb:15,Kb:16,Lb:17,ob:18,nb:19,pb:20},nN=g.FetchXmlHttpFactory=tz,nO=g.WebChannel=eZ,nP=g.XhrIo=tX,nL=n(3454);let nM="@firebase/firestore";/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class nF{constructor(e){this.uid=e}isAuthenticated(){return null!=this.uid}toKey(){return this.isAuthenticated()?"uid:"+this.uid:"anonymous-user"}isEqual(e){return e.uid===this.uid}}nF.UNAUTHENTICATED=new nF(null),nF.GOOGLE_CREDENTIALS=new nF("google-credentials-uid"),nF.FIRST_PARTY=new nF("first-party-uid"),nF.MOCK_USER=new nF("mock-user");/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let nU="9.15.0",nV=new f.Yd("@firebase/firestore");function nq(){return nV.logLevel}function nB(e){nV.setLogLevel(e)}function nj(e,...t){if(nV.logLevel<=f.in.DEBUG){let n=t.map(nG);nV.debug(`Firestore (${nU}): ${e}`,...n)}}function n$(e,...t){if(nV.logLevel<=f.in.ERROR){let n=t.map(nG);nV.error(`Firestore (${nU}): ${e}`,...n)}}function nz(e,...t){if(nV.logLevel<=f.in.WARN){let n=t.map(nG);nV.warn(`Firestore (${nU}): ${e}`,...n)}}function nG(e){if("string"==typeof e)return e;try{return JSON.stringify(e)}catch(t){return e}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function nK(e="Unexpected state"){let t=`FIRESTORE (${nU}) INTERNAL ASSERTION FAILED: `+e;throw n$(t),Error(t)}function nH(e,t){e||nK()}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let nW={OK:"ok",CANCELLED:"cancelled",UNKNOWN:"unknown",INVALID_ARGUMENT:"invalid-argument",DEADLINE_EXCEEDED:"deadline-exceeded",NOT_FOUND:"not-found",ALREADY_EXISTS:"already-exists",PERMISSION_DENIED:"permission-denied",UNAUTHENTICATED:"unauthenticated",RESOURCE_EXHAUSTED:"resource-exhausted",FAILED_PRECONDITION:"failed-precondition",ABORTED:"aborted",OUT_OF_RANGE:"out-of-range",UNIMPLEMENTED:"unimplemented",INTERNAL:"internal",UNAVAILABLE:"unavailable",DATA_LOSS:"data-loss"};class nQ extends p.ZR{constructor(e,t){super(e,t),this.code=e,this.message=t,this.toString=()=>`${this.name}: [code=${this.code}]: ${this.message}`}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class nY{constructor(){this.promise=new Promise((e,t)=>{this.resolve=e,this.reject=t})}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class nX{constructor(e,t){this.user=t,this.type="OAuth",this.headers=new Map,this.headers.set("Authorization",`Bearer ${e}`)}}class nJ{getToken(){return Promise.resolve(null)}invalidateToken(){}start(e,t){e.enqueueRetryable(()=>t(nF.UNAUTHENTICATED))}shutdown(){}}class nZ{constructor(e){this.token=e,this.changeListener=null}getToken(){return Promise.resolve(this.token)}invalidateToken(){}start(e,t){this.changeListener=t,e.enqueueRetryable(()=>t(this.token.user))}shutdown(){this.changeListener=null}}class n0{constructor(e){this.t=e,this.currentUser=nF.UNAUTHENTICATED,this.i=0,this.forceRefresh=!1,this.auth=null}start(e,t){let n=this.i,r=e=>this.i!==n?(n=this.i,t(e)):Promise.resolve(),i=new nY;this.o=()=>{this.i++,this.currentUser=this.u(),i.resolve(),i=new nY,e.enqueueRetryable(()=>r(this.currentUser))};let s=()=>{let t=i;e.enqueueRetryable(async()=>{await t.promise,await r(this.currentUser)})},a=e=>{nj("FirebaseAuthCredentialsProvider","Auth detected"),this.auth=e,this.auth.addAuthTokenListener(this.o),s()};this.t.onInit(e=>a(e)),setTimeout(()=>{if(!this.auth){let e=this.t.getImmediate({optional:!0});e?a(e):(nj("FirebaseAuthCredentialsProvider","Auth not yet detected"),i.resolve(),i=new nY)}},0),s()}getToken(){let e=this.i,t=this.forceRefresh;return this.forceRefresh=!1,this.auth?this.auth.getToken(t).then(t=>this.i!==e?(nj("FirebaseAuthCredentialsProvider","getToken aborted due to token change."),this.getToken()):t?("string"==typeof t.accessToken||nK(),new nX(t.accessToken,this.currentUser)):null):Promise.resolve(null)}invalidateToken(){this.forceRefresh=!0}shutdown(){this.auth&&this.auth.removeAuthTokenListener(this.o)}u(){let e=this.auth&&this.auth.getUid();return null===e||"string"==typeof e||nK(),new nF(e)}}class n1{constructor(e,t,n,r){this.h=e,this.l=t,this.m=n,this.g=r,this.type="FirstParty",this.user=nF.FIRST_PARTY,this.p=new Map}I(){return this.g?this.g():("object"==typeof this.h&&null!==this.h&&this.h.auth&&this.h.auth.getAuthHeaderValueForFirstParty||nK(),this.h.auth.getAuthHeaderValueForFirstParty([]))}get headers(){this.p.set("X-Goog-AuthUser",this.l);let e=this.I();return e&&this.p.set("Authorization",e),this.m&&this.p.set("X-Goog-Iam-Authorization-Token",this.m),this.p}}class n2{constructor(e,t,n,r){this.h=e,this.l=t,this.m=n,this.g=r}getToken(){return Promise.resolve(new n1(this.h,this.l,this.m,this.g))}start(e,t){e.enqueueRetryable(()=>t(nF.FIRST_PARTY))}shutdown(){}invalidateToken(){}}class n4{constructor(e){this.value=e,this.type="AppCheck",this.headers=new Map,e&&e.length>0&&this.headers.set("x-firebase-appcheck",this.value)}}class n3{constructor(e){this.T=e,this.forceRefresh=!1,this.appCheck=null,this.A=null}start(e,t){let n=e=>{null!=e.error&&nj("FirebaseAppCheckTokenProvider",`Error getting App Check token; using placeholder token instead. Error: ${e.error.message}`);let n=e.token!==this.A;return this.A=e.token,nj("FirebaseAppCheckTokenProvider",`Received ${n?"new":"existing"} token.`),n?t(e.token):Promise.resolve()};this.o=t=>{e.enqueueRetryable(()=>n(t))};let r=e=>{nj("FirebaseAppCheckTokenProvider","AppCheck detected"),this.appCheck=e,this.appCheck.addTokenListener(this.o)};this.T.onInit(e=>r(e)),setTimeout(()=>{if(!this.appCheck){let e=this.T.getImmediate({optional:!0});e?r(e):nj("FirebaseAppCheckTokenProvider","AppCheck not yet detected")}},0)}getToken(){let e=this.forceRefresh;return this.forceRefresh=!1,this.appCheck?this.appCheck.getToken(e).then(e=>e?("string"==typeof e.token||nK(),this.A=e.token,new n4(e.token)):null):Promise.resolve(null)}invalidateToken(){this.forceRefresh=!0}shutdown(){this.appCheck&&this.appCheck.removeTokenListener(this.o)}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class n6{static R(){let e="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",t=Math.floor(256/e.length)*e.length,n="";for(;n.length<20;){let r=/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function(e){let t="undefined"!=typeof self&&(self.crypto||self.msCrypto),n=new Uint8Array(e);if(t&&"function"==typeof t.getRandomValues)t.getRandomValues(n);else for(let r=0;r<e;r++)n[r]=Math.floor(256*Math.random());return n}(40);for(let i=0;i<r.length;++i)n.length<20&&r[i]<t&&(n+=e.charAt(r[i]%e.length))}return n}}function n5(e,t){return e<t?-1:e>t?1:0}function n9(e,t,n){return e.length===t.length&&e.every((e,r)=>n(e,t[r]))}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class n8{constructor(e,t){if(this.seconds=e,this.nanoseconds=t,t<0||t>=1e9)throw new nQ(nW.INVALID_ARGUMENT,"Timestamp nanoseconds out of range: "+t);if(e<-62135596800||e>=253402300800)throw new nQ(nW.INVALID_ARGUMENT,"Timestamp seconds out of range: "+e)}static now(){return n8.fromMillis(Date.now())}static fromDate(e){return n8.fromMillis(e.getTime())}static fromMillis(e){let t=Math.floor(e/1e3);return new n8(t,Math.floor(1e6*(e-1e3*t)))}toDate(){return new Date(this.toMillis())}toMillis(){return 1e3*this.seconds+this.nanoseconds/1e6}_compareTo(e){return this.seconds===e.seconds?n5(this.nanoseconds,e.nanoseconds):n5(this.seconds,e.seconds)}isEqual(e){return e.seconds===this.seconds&&e.nanoseconds===this.nanoseconds}toString(){return"Timestamp(seconds="+this.seconds+", nanoseconds="+this.nanoseconds+")"}toJSON(){return{seconds:this.seconds,nanoseconds:this.nanoseconds}}valueOf(){let e=this.seconds- -62135596800;return String(e).padStart(12,"0")+"."+String(this.nanoseconds).padStart(9,"0")}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class n7{constructor(e){this.timestamp=e}static fromTimestamp(e){return new n7(e)}static min(){return new n7(new n8(0,0))}static max(){return new n7(new n8(253402300799,999999999))}compareTo(e){return this.timestamp._compareTo(e.timestamp)}isEqual(e){return this.timestamp.isEqual(e.timestamp)}toMicroseconds(){return 1e6*this.timestamp.seconds+this.timestamp.nanoseconds/1e3}toString(){return"SnapshotVersion("+this.timestamp.toString()+")"}toTimestamp(){return this.timestamp}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class re{constructor(e,t,n){void 0===t?t=0:t>e.length&&nK(),void 0===n?n=e.length-t:n>e.length-t&&nK(),this.segments=e,this.offset=t,this.len=n}get length(){return this.len}isEqual(e){return 0===re.comparator(this,e)}child(e){let t=this.segments.slice(this.offset,this.limit());return e instanceof re?e.forEach(e=>{t.push(e)}):t.push(e),this.construct(t)}limit(){return this.offset+this.length}popFirst(e){return e=void 0===e?1:e,this.construct(this.segments,this.offset+e,this.length-e)}popLast(){return this.construct(this.segments,this.offset,this.length-1)}firstSegment(){return this.segments[this.offset]}lastSegment(){return this.get(this.length-1)}get(e){return this.segments[this.offset+e]}isEmpty(){return 0===this.length}isPrefixOf(e){if(e.length<this.length)return!1;for(let t=0;t<this.length;t++)if(this.get(t)!==e.get(t))return!1;return!0}isImmediateParentOf(e){if(this.length+1!==e.length)return!1;for(let t=0;t<this.length;t++)if(this.get(t)!==e.get(t))return!1;return!0}forEach(e){for(let t=this.offset,n=this.limit();t<n;t++)e(this.segments[t])}toArray(){return this.segments.slice(this.offset,this.limit())}static comparator(e,t){let n=Math.min(e.length,t.length);for(let r=0;r<n;r++){let i=e.get(r),s=t.get(r);if(i<s)return -1;if(i>s)return 1}return e.length<t.length?-1:e.length>t.length?1:0}}class rt extends re{construct(e,t,n){return new rt(e,t,n)}canonicalString(){return this.toArray().join("/")}toString(){return this.canonicalString()}static fromString(...e){let t=[];for(let n of e){if(n.indexOf("//")>=0)throw new nQ(nW.INVALID_ARGUMENT,`Invalid segment (${n}). Paths must not contain // in them.`);t.push(...n.split("/").filter(e=>e.length>0))}return new rt(t)}static emptyPath(){return new rt([])}}let rn=/^[_a-zA-Z][_a-zA-Z0-9]*$/;class rr extends re{construct(e,t,n){return new rr(e,t,n)}static isValidIdentifier(e){return rn.test(e)}canonicalString(){return this.toArray().map(e=>(e=e.replace(/\\/g,"\\\\").replace(/`/g,"\\`"),rr.isValidIdentifier(e)||(e="`"+e+"`"),e)).join(".")}toString(){return this.canonicalString()}isKeyField(){return 1===this.length&&"__name__"===this.get(0)}static keyField(){return new rr(["__name__"])}static fromServerFormat(e){let t=[],n="",r=0,i=()=>{if(0===n.length)throw new nQ(nW.INVALID_ARGUMENT,`Invalid field path (${e}). Paths must not be empty, begin with '.', end with '.', or contain '..'`);t.push(n),n=""},s=!1;for(;r<e.length;){let a=e[r];if("\\"===a){if(r+1===e.length)throw new nQ(nW.INVALID_ARGUMENT,"Path has trailing escape character: "+e);let o=e[r+1];if("\\"!==o&&"."!==o&&"`"!==o)throw new nQ(nW.INVALID_ARGUMENT,"Path has invalid escape sequence: "+e);n+=o,r+=2}else"`"===a?(s=!s,r++):"."!==a||s?(n+=a,r++):(i(),r++)}if(i(),s)throw new nQ(nW.INVALID_ARGUMENT,"Unterminated ` in path: "+e);return new rr(t)}static emptyPath(){return new rr([])}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class ri{constructor(e){this.path=e}static fromPath(e){return new ri(rt.fromString(e))}static fromName(e){return new ri(rt.fromString(e).popFirst(5))}static empty(){return new ri(rt.emptyPath())}get collectionGroup(){return this.path.popLast().lastSegment()}hasCollectionId(e){return this.path.length>=2&&this.path.get(this.path.length-2)===e}getCollectionGroup(){return this.path.get(this.path.length-2)}getCollectionPath(){return this.path.popLast()}isEqual(e){return null!==e&&0===rt.comparator(this.path,e.path)}toString(){return this.path.toString()}static comparator(e,t){return rt.comparator(e.path,t.path)}static isDocumentKey(e){return e.length%2==0}static fromSegments(e){return new ri(new rt(e.slice()))}}/**
 * @license
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class rs{constructor(e,t,n,r){this.indexId=e,this.collectionGroup=t,this.fields=n,this.indexState=r}}function ra(e){return e.fields.find(e=>2===e.kind)}function ro(e){return e.fields.filter(e=>2!==e.kind)}rs.UNKNOWN_ID=-1;class rl{constructor(e,t){this.fieldPath=e,this.kind=t}}class ru{constructor(e,t){this.sequenceNumber=e,this.offset=t}static empty(){return new ru(0,rd.min())}}function rc(e,t){let n=e.toTimestamp().seconds,r=e.toTimestamp().nanoseconds+1,i=n7.fromTimestamp(1e9===r?new n8(n+1,0):new n8(n,r));return new rd(i,ri.empty(),t)}function rh(e){return new rd(e.readTime,e.key,-1)}class rd{constructor(e,t,n){this.readTime=e,this.documentKey=t,this.largestBatchId=n}static min(){return new rd(n7.min(),ri.empty(),-1)}static max(){return new rd(n7.max(),ri.empty(),-1)}}function rf(e,t){let n=e.readTime.compareTo(t.readTime);return 0!==n?n:0!==(n=ri.comparator(e.documentKey,t.documentKey))?n:n5(e.largestBatchId,t.largestBatchId)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let rp="The current tab is not in the required state to perform this operation. It might be necessary to refresh the browser tab.";class rm{constructor(){this.onCommittedListeners=[]}addOnCommittedListener(e){this.onCommittedListeners.push(e)}raiseOnCommittedEvent(){this.onCommittedListeners.forEach(e=>e())}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function rg(e){if(e.code!==nW.FAILED_PRECONDITION||e.message!==rp)throw e;nj("LocalStore","Unexpectedly lost primary lease")}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class ry{constructor(e){this.nextCallback=null,this.catchCallback=null,this.result=void 0,this.error=void 0,this.isDone=!1,this.callbackAttached=!1,e(e=>{this.isDone=!0,this.result=e,this.nextCallback&&this.nextCallback(e)},e=>{this.isDone=!0,this.error=e,this.catchCallback&&this.catchCallback(e)})}catch(e){return this.next(void 0,e)}next(e,t){return this.callbackAttached&&nK(),this.callbackAttached=!0,this.isDone?this.error?this.wrapFailure(t,this.error):this.wrapSuccess(e,this.result):new ry((n,r)=>{this.nextCallback=t=>{this.wrapSuccess(e,t).next(n,r)},this.catchCallback=e=>{this.wrapFailure(t,e).next(n,r)}})}toPromise(){return new Promise((e,t)=>{this.next(e,t)})}wrapUserFunction(e){try{let t=e();return t instanceof ry?t:ry.resolve(t)}catch(n){return ry.reject(n)}}wrapSuccess(e,t){return e?this.wrapUserFunction(()=>e(t)):ry.resolve(t)}wrapFailure(e,t){return e?this.wrapUserFunction(()=>e(t)):ry.reject(t)}static resolve(e){return new ry((t,n)=>{t(e)})}static reject(e){return new ry((t,n)=>{n(e)})}static waitFor(e){return new ry((t,n)=>{let r=0,i=0,s=!1;e.forEach(e=>{++r,e.next(()=>{++i,s&&i===r&&t()},e=>n(e))}),s=!0,i===r&&t()})}static or(e){let t=ry.resolve(!1);for(let n of e)t=t.next(e=>e?ry.resolve(e):n());return t}static forEach(e,t){let n=[];return e.forEach((e,r)=>{n.push(t.call(this,e,r))}),this.waitFor(n)}static mapArray(e,t){return new ry((n,r)=>{let i=e.length,s=Array(i),a=0;for(let o=0;o<i;o++){let l=o;t(e[l]).next(e=>{s[l]=e,++a===i&&n(s)},e=>r(e))}})}static doWhile(e,t){return new ry((n,r)=>{let i=()=>{!0===e()?t().next(()=>{i()},r):n()};i()})}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class rv{constructor(e,t){this.action=e,this.transaction=t,this.aborted=!1,this.P=new nY,this.transaction.oncomplete=()=>{this.P.resolve()},this.transaction.onabort=()=>{t.error?this.P.reject(new rb(e,t.error)):this.P.resolve()},this.transaction.onerror=t=>{let n=rk(t.target.error);this.P.reject(new rb(e,n))}}static open(e,t,n,r){try{return new rv(t,e.transaction(r,n))}catch(i){throw new rb(t,i)}}get v(){return this.P.promise}abort(e){e&&this.P.reject(e),this.aborted||(nj("SimpleDb","Aborting transaction:",e?e.message:"Client-initiated abort"),this.aborted=!0,this.transaction.abort())}V(){let e=this.transaction;this.aborted||"function"!=typeof e.commit||e.commit()}store(e){let t=this.transaction.objectStore(e);return new rT(t)}}class rw{constructor(e,t,n){this.name=e,this.version=t,this.S=n,12.2===rw.D((0,p.z$)())&&n$("Firestore persistence suffers from a bug in iOS 12.2 Safari that may cause your app to stop working. See https://stackoverflow.com/q/56496296/110915 for details and a potential workaround.")}static delete(e){return nj("SimpleDb","Removing database:",e),rE(window.indexedDB.deleteDatabase(e)).toPromise()}static C(){if(!(0,p.hl)())return!1;if(rw.N())return!0;let e=(0,p.z$)(),t=rw.D(e),n=rw.k(e);return!(e.indexOf("MSIE ")>0||e.indexOf("Trident/")>0||e.indexOf("Edge/")>0||0<t&&t<10||0<n&&n<4.5)}static N(){var e;return void 0!==nL&&"YES"===(null===(e=nL.env)||void 0===e?void 0:e.O)}static M(e,t){return e.store(t)}static D(e){let t=e.match(/i(?:phone|pad|pod) os ([\d_]+)/i),n=t?t[1].split("_").slice(0,2).join("."):"-1";return Number(n)}static k(e){let t=e.match(/Android ([\d.]+)/i),n=t?t[1].split(".").slice(0,2).join("."):"-1";return Number(n)}async F(e){return this.db||(nj("SimpleDb","Opening database:",this.name),this.db=await new Promise((t,n)=>{let r=indexedDB.open(this.name,this.version);r.onsuccess=e=>{let n=e.target.result;t(n)},r.onblocked=()=>{n(new rb(e,"Cannot upgrade IndexedDB schema while another tab is open. Close all tabs that access Firestore and reload this page to proceed."))},r.onerror=t=>{let r=t.target.error;"VersionError"===r.name?n(new nQ(nW.FAILED_PRECONDITION,"A newer version of the Firestore SDK was previously used and so the persisted data is not compatible with the version of the SDK you are now using. The SDK will operate with persistence disabled. If you need persistence, please re-upgrade to a newer version of the SDK or else clear the persisted IndexedDB data for your app to start fresh.")):"InvalidStateError"===r.name?n(new nQ(nW.FAILED_PRECONDITION,"Unable to open an IndexedDB connection. This could be due to running in a private browsing session on a browser whose private browsing sessions do not support IndexedDB: "+r)):n(new rb(e,r))},r.onupgradeneeded=e=>{nj("SimpleDb",'Database "'+this.name+'" requires upgrade from version:',e.oldVersion);let t=e.target.result;this.S.$(t,r.transaction,e.oldVersion,this.version).next(()=>{nj("SimpleDb","Database upgrade to version "+this.version+" complete")})}})),this.B&&(this.db.onversionchange=e=>this.B(e)),this.db}L(e){this.B=e,this.db&&(this.db.onversionchange=t=>e(t))}async runTransaction(e,t,n,r){let i="readonly"===t,s=0;for(;;){++s;try{this.db=await this.F(e);let a=rv.open(this.db,e,i?"readonly":"readwrite",n),o=r(a).next(e=>(a.V(),e)).catch(e=>(a.abort(e),ry.reject(e))).toPromise();return o.catch(()=>{}),await a.v,o}catch(u){let l="FirebaseError"!==u.name&&s<3;if(nj("SimpleDb","Transaction failed with error:",u.message,"Retrying:",l),this.close(),!l)return Promise.reject(u)}}}close(){this.db&&this.db.close(),this.db=void 0}}class r_{constructor(e){this.q=e,this.U=!1,this.K=null}get isDone(){return this.U}get G(){return this.K}set cursor(e){this.q=e}done(){this.U=!0}j(e){this.K=e}delete(){return rE(this.q.delete())}}class rb extends nQ{constructor(e,t){super(nW.UNAVAILABLE,`IndexedDB transaction '${e}' failed: ${t}`),this.name="IndexedDbTransactionError"}}function rI(e){return"IndexedDbTransactionError"===e.name}class rT{constructor(e){this.store=e}put(e,t){let n;return void 0!==t?(nj("SimpleDb","PUT",this.store.name,e,t),n=this.store.put(t,e)):(nj("SimpleDb","PUT",this.store.name,"<auto-key>",e),n=this.store.put(e)),rE(n)}add(e){return nj("SimpleDb","ADD",this.store.name,e,e),rE(this.store.add(e))}get(e){return rE(this.store.get(e)).next(t=>(void 0===t&&(t=null),nj("SimpleDb","GET",this.store.name,e,t),t))}delete(e){return nj("SimpleDb","DELETE",this.store.name,e),rE(this.store.delete(e))}count(){return nj("SimpleDb","COUNT",this.store.name),rE(this.store.count())}W(e,t){let n=this.options(e,t);if(n.index||"function"!=typeof this.store.getAll){let r=this.cursor(n),i=[];return this.H(r,(e,t)=>{i.push(t)}).next(()=>i)}{let s=this.store.getAll(n.range);return new ry((e,t)=>{s.onerror=e=>{t(e.target.error)},s.onsuccess=t=>{e(t.target.result)}})}}J(e,t){let n=this.store.getAll(e,null===t?void 0:t);return new ry((e,t)=>{n.onerror=e=>{t(e.target.error)},n.onsuccess=t=>{e(t.target.result)}})}Y(e,t){nj("SimpleDb","DELETE ALL",this.store.name);let n=this.options(e,t);n.X=!1;let r=this.cursor(n);return this.H(r,(e,t,n)=>n.delete())}Z(e,t){let n;t?n=e:(n={},t=e);let r=this.cursor(n);return this.H(r,t)}tt(e){let t=this.cursor({});return new ry((n,r)=>{t.onerror=e=>{let t=rk(e.target.error);r(t)},t.onsuccess=t=>{let r=t.target.result;r?e(r.primaryKey,r.value).next(e=>{e?r.continue():n()}):n()}})}H(e,t){let n=[];return new ry((r,i)=>{e.onerror=e=>{i(e.target.error)},e.onsuccess=e=>{let i=e.target.result;if(!i)return void r();let s=new r_(i),a=t(i.primaryKey,i.value,s);if(a instanceof ry){let o=a.catch(e=>(s.done(),ry.reject(e)));n.push(o)}s.isDone?r():null===s.G?i.continue():i.continue(s.G)}}).next(()=>ry.waitFor(n))}options(e,t){let n;return void 0!==e&&("string"==typeof e?n=e:t=e),{index:n,range:t}}cursor(e){let t="next";if(e.reverse&&(t="prev"),e.index){let n=this.store.index(e.index);return e.X?n.openKeyCursor(e.range,t):n.openCursor(e.range,t)}return this.store.openCursor(e.range,t)}}function rE(e){return new ry((t,n)=>{e.onsuccess=e=>{let n=e.target.result;t(n)},e.onerror=e=>{let t=rk(e.target.error);n(t)}})}let rS=!1;function rk(e){let t=rw.D((0,p.z$)());if(t>=12.2&&t<13){let n="An internal error was encountered in the Indexed Database server";if(e.message.indexOf(n)>=0){let r=new nQ("internal",`IOS_INDEXEDDB_BUG1: IndexedDb has thrown '${n}'. This is likely due to an unavoidable bug in iOS. See https://stackoverflow.com/q/56496296/110915 for details and a potential workaround.`);return rS||(rS=!0,setTimeout(()=>{throw r},0)),r}}return e}class rA{constructor(e,t){this.asyncQueue=e,this.et=t,this.task=null}start(){this.nt(15e3)}stop(){this.task&&(this.task.cancel(),this.task=null)}get started(){return null!==this.task}nt(e){nj("IndexBackiller",`Scheduled in ${e}ms`),this.task=this.asyncQueue.enqueueAfterDelay("index_backfill",e,async()=>{this.task=null;try{nj("IndexBackiller",`Documents written: ${await this.et.st()}`)}catch(e){rI(e)?nj("IndexBackiller","Ignoring IndexedDB error during index backfill: ",e):await rg(e)}await this.nt(6e4)})}}class rC{constructor(e,t){this.localStore=e,this.persistence=t}async st(e=50){return this.persistence.runTransaction("Backfill Indexes","readwrite-primary",t=>this.it(t,e))}it(e,t){let n=new Set,r=t,i=!0;return ry.doWhile(()=>!0===i&&r>0,()=>this.localStore.indexManager.getNextCollectionGroupToUpdate(e).next(t=>{if(null!==t&&!n.has(t))return nj("IndexBackiller",`Processing collection: ${t}`),this.rt(e,t,r).next(e=>{r-=e,n.add(t)});i=!1})).next(()=>t-r)}rt(e,t,n){return this.localStore.indexManager.getMinOffsetFromCollectionGroup(e,t).next(r=>this.localStore.localDocuments.getNextDocuments(e,t,r,n).next(n=>{let i=n.changes;return this.localStore.indexManager.updateIndexEntries(e,i).next(()=>this.ot(r,n)).next(n=>(nj("IndexBackiller",`Updating offset: ${n}`),this.localStore.indexManager.updateCollectionGroup(e,t,n))).next(()=>i.size)}))}ot(e,t){let n=e;return t.changes.forEach((e,t)=>{let r=rh(t);rf(r,n)>0&&(n=r)}),new rd(n.readTime,n.documentKey,Math.max(t.batchId,e.largestBatchId))}}/**
 * @license
 * Copyright 2018 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class rx{constructor(e,t){this.previousValue=e,t&&(t.sequenceNumberHandler=e=>this.ut(e),this.ct=e=>t.writeSequenceNumber(e))}ut(e){return this.previousValue=Math.max(e,this.previousValue),this.previousValue}next(){let e=++this.previousValue;return this.ct&&this.ct(e),e}}rx.at=-1;/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class rR{constructor(e,t,n,r,i,s,a,o){this.databaseId=e,this.appId=t,this.persistenceKey=n,this.host=r,this.ssl=i,this.forceLongPolling=s,this.autoDetectLongPolling=a,this.useFetchStreams=o}}class rD{constructor(e,t){this.projectId=e,this.database=t||"(default)"}static empty(){return new rD("","")}get isDefaultDatabase(){return"(default)"===this.database}isEqual(e){return e instanceof rD&&e.projectId===this.projectId&&e.database===this.database}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function rN(e){let t=0;for(let n in e)Object.prototype.hasOwnProperty.call(e,n)&&t++;return t}function rO(e,t){for(let n in e)Object.prototype.hasOwnProperty.call(e,n)&&t(n,e[n])}function rP(e){for(let t in e)if(Object.prototype.hasOwnProperty.call(e,t))return!1;return!0}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function rL(e){return null==e}function rM(e){return 0===e&&1/e==-1/0}function rF(e){return"number"==typeof e&&Number.isInteger(e)&&!rM(e)&&e<=Number.MAX_SAFE_INTEGER&&e>=Number.MIN_SAFE_INTEGER}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function rU(){return"undefined"!=typeof atob}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class rV{constructor(e){this.binaryString=e}static fromBase64String(e){let t=atob(e);return new rV(t)}static fromUint8Array(e){let t=function(e){let t="";for(let n=0;n<e.length;++n)t+=String.fromCharCode(e[n]);return t}(e);return new rV(t)}[Symbol.iterator](){let e=0;return{next:()=>e<this.binaryString.length?{value:this.binaryString.charCodeAt(e++),done:!1}:{value:void 0,done:!0}}}toBase64(){return btoa(this.binaryString)}toUint8Array(){return function(e){let t=new Uint8Array(e.length);for(let n=0;n<e.length;n++)t[n]=e.charCodeAt(n);return t}(this.binaryString)}approximateByteSize(){return 2*this.binaryString.length}compareTo(e){return n5(this.binaryString,e.binaryString)}isEqual(e){return this.binaryString===e.binaryString}}rV.EMPTY_BYTE_STRING=new rV("");let rq=RegExp(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.(\d+))?Z$/);function rB(e){if(e||nK(),"string"==typeof e){let t=0,n=rq.exec(e);if(n||nK(),n[1]){let r=n[1];t=Number(r=(r+"000000000").substr(0,9))}let i=new Date(e);return{seconds:Math.floor(i.getTime()/1e3),nanos:t}}return{seconds:rj(e.seconds),nanos:rj(e.nanos)}}function rj(e){return"number"==typeof e?e:"string"==typeof e?Number(e):0}function r$(e){return"string"==typeof e?rV.fromBase64String(e):rV.fromUint8Array(e)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function rz(e){var t,n;return"server_timestamp"===(null===(n=((null===(t=null==e?void 0:e.mapValue)||void 0===t?void 0:t.fields)||{}).__type__)||void 0===n?void 0:n.stringValue)}function rG(e){let t=rB(e.mapValue.fields.__local_write_time__.timestampValue);return new n8(t.seconds,t.nanos)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let rK={mapValue:{fields:{__type__:{stringValue:"__max__"}}}},rH={nullValue:"NULL_VALUE"};function rW(e){return"nullValue"in e?0:"booleanValue"in e?1:"integerValue"in e||"doubleValue"in e?2:"timestampValue"in e?3:"stringValue"in e?5:"bytesValue"in e?6:"referenceValue"in e?7:"geoPointValue"in e?8:"arrayValue"in e?9:"mapValue"in e?rz(e)?4:r9(e)?9007199254740991:10:nK()}function rQ(e,t){if(e===t)return!0;let n=rW(e);if(n!==rW(t))return!1;switch(n){case 0:case 9007199254740991:return!0;case 1:return e.booleanValue===t.booleanValue;case 4:return rG(e).isEqual(rG(t));case 3:return function(e,t){if("string"==typeof e.timestampValue&&"string"==typeof t.timestampValue&&e.timestampValue.length===t.timestampValue.length)return e.timestampValue===t.timestampValue;let n=rB(e.timestampValue),r=rB(t.timestampValue);return n.seconds===r.seconds&&n.nanos===r.nanos}(e,t);case 5:return e.stringValue===t.stringValue;case 6:return r$(e.bytesValue).isEqual(r$(t.bytesValue));case 7:return e.referenceValue===t.referenceValue;case 8:return rj(e.geoPointValue.latitude)===rj(t.geoPointValue.latitude)&&rj(e.geoPointValue.longitude)===rj(t.geoPointValue.longitude);case 2:return function(e,t){if("integerValue"in e&&"integerValue"in t)return rj(e.integerValue)===rj(t.integerValue);if("doubleValue"in e&&"doubleValue"in t){let n=rj(e.doubleValue),r=rj(t.doubleValue);return n===r?rM(n)===rM(r):isNaN(n)&&isNaN(r)}return!1}(e,t);case 9:return n9(e.arrayValue.values||[],t.arrayValue.values||[],rQ);case 10:return function(e,t){let n=e.mapValue.fields||{},r=t.mapValue.fields||{};if(rN(n)!==rN(r))return!1;for(let i in n)if(n.hasOwnProperty(i)&&(void 0===r[i]||!rQ(n[i],r[i])))return!1;return!0}(e,t);default:return nK()}}function rY(e,t){return void 0!==(e.values||[]).find(e=>rQ(e,t))}function rX(e,t){if(e===t)return 0;let n=rW(e),r=rW(t);if(n!==r)return n5(n,r);switch(n){case 0:case 9007199254740991:return 0;case 1:return n5(e.booleanValue,t.booleanValue);case 2:return function(e,t){let n=rj(e.integerValue||e.doubleValue),r=rj(t.integerValue||t.doubleValue);return n<r?-1:n>r?1:n===r?0:isNaN(n)?isNaN(r)?0:-1:1}(e,t);case 3:return rJ(e.timestampValue,t.timestampValue);case 4:return rJ(rG(e),rG(t));case 5:return n5(e.stringValue,t.stringValue);case 6:return function(e,t){let n=r$(e),r=r$(t);return n.compareTo(r)}(e.bytesValue,t.bytesValue);case 7:return function(e,t){let n=e.split("/"),r=t.split("/");for(let i=0;i<n.length&&i<r.length;i++){let s=n5(n[i],r[i]);if(0!==s)return s}return n5(n.length,r.length)}(e.referenceValue,t.referenceValue);case 8:return function(e,t){let n=n5(rj(e.latitude),rj(t.latitude));return 0!==n?n:n5(rj(e.longitude),rj(t.longitude))}(e.geoPointValue,t.geoPointValue);case 9:return function(e,t){let n=e.values||[],r=t.values||[];for(let i=0;i<n.length&&i<r.length;++i){let s=rX(n[i],r[i]);if(s)return s}return n5(n.length,r.length)}(e.arrayValue,t.arrayValue);case 10:return function(e,t){if(e===rK.mapValue&&t===rK.mapValue)return 0;if(e===rK.mapValue)return 1;if(t===rK.mapValue)return -1;let n=e.fields||{},r=Object.keys(n),i=t.fields||{},s=Object.keys(i);r.sort(),s.sort();for(let a=0;a<r.length&&a<s.length;++a){let o=n5(r[a],s[a]);if(0!==o)return o;let l=rX(n[r[a]],i[s[a]]);if(0!==l)return l}return n5(r.length,s.length)}(e.mapValue,t.mapValue);default:throw nK()}}function rJ(e,t){if("string"==typeof e&&"string"==typeof t&&e.length===t.length)return n5(e,t);let n=rB(e),r=rB(t),i=n5(n.seconds,r.seconds);return 0!==i?i:n5(n.nanos,r.nanos)}function rZ(e){var t,n;return"nullValue"in e?"null":"booleanValue"in e?""+e.booleanValue:"integerValue"in e?""+e.integerValue:"doubleValue"in e?""+e.doubleValue:"timestampValue"in e?function(e){let t=rB(e);return`time(${t.seconds},${t.nanos})`}(e.timestampValue):"stringValue"in e?e.stringValue:"bytesValue"in e?r$(e.bytesValue).toBase64():"referenceValue"in e?(n=e.referenceValue,ri.fromName(n).toString()):"geoPointValue"in e?`geo(${(t=e.geoPointValue).latitude},${t.longitude})`:"arrayValue"in e?function(e){let t="[",n=!0;for(let r of e.values||[])n?n=!1:t+=",",t+=rZ(r);return t+"]"}(e.arrayValue):"mapValue"in e?function(e){let t=Object.keys(e.fields||{}).sort(),n="{",r=!0;for(let i of t)r?r=!1:n+=",",n+=`${i}:${rZ(e.fields[i])}`;return n+"}"}(e.mapValue):nK()}function r0(e,t){return{referenceValue:`projects/${e.projectId}/databases/${e.database}/documents/${t.path.canonicalString()}`}}function r1(e){return!!e&&"integerValue"in e}function r2(e){return!!e&&"arrayValue"in e}function r4(e){return!!e&&"nullValue"in e}function r3(e){return!!e&&"doubleValue"in e&&isNaN(Number(e.doubleValue))}function r6(e){return!!e&&"mapValue"in e}function r5(e){if(e.geoPointValue)return{geoPointValue:Object.assign({},e.geoPointValue)};if(e.timestampValue&&"object"==typeof e.timestampValue)return{timestampValue:Object.assign({},e.timestampValue)};if(e.mapValue){let t={mapValue:{fields:{}}};return rO(e.mapValue.fields,(e,n)=>t.mapValue.fields[e]=r5(n)),t}if(e.arrayValue){let n={arrayValue:{values:[]}};for(let r=0;r<(e.arrayValue.values||[]).length;++r)n.arrayValue.values[r]=r5(e.arrayValue.values[r]);return n}return Object.assign({},e)}function r9(e){return"__max__"===(((e.mapValue||{}).fields||{}).__type__||{}).stringValue}function r8(e,t){let n=rX(e.value,t.value);return 0!==n?n:e.inclusive&&!t.inclusive?-1:!e.inclusive&&t.inclusive?1:0}function r7(e,t){let n=rX(e.value,t.value);return 0!==n?n:e.inclusive&&!t.inclusive?1:!e.inclusive&&t.inclusive?-1:0}/**
 * @license
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class ie{constructor(e,t){this.position=e,this.inclusive=t}}function it(e,t,n){let r=0;for(let i=0;i<e.position.length;i++){let s=t[i],a=e.position[i];if(r=s.field.isKeyField()?ri.comparator(ri.fromName(a.referenceValue),n.key):rX(a,n.data.field(s.field)),"desc"===s.dir&&(r*=-1),0!==r)break}return r}function ir(e,t){if(null===e)return null===t;if(null===t||e.inclusive!==t.inclusive||e.position.length!==t.position.length)return!1;for(let n=0;n<e.position.length;n++)if(!rQ(e.position[n],t.position[n]))return!1;return!0}/**
 * @license
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class ii{}class is extends ii{constructor(e,t,n){super(),this.field=e,this.op=t,this.value=n}static create(e,t,n){return e.isKeyField()?"in"===t||"not-in"===t?this.createKeyFieldInFilter(e,t,n):new ih(e,t,n):"array-contains"===t?new ig(e,n):"in"===t?new iy(e,n):"not-in"===t?new iv(e,n):"array-contains-any"===t?new iw(e,n):new is(e,t,n)}static createKeyFieldInFilter(e,t,n){return"in"===t?new id(e,n):new ip(e,n)}matches(e){let t=e.data.field(this.field);return"!="===this.op?null!==t&&this.matchesComparison(rX(t,this.value)):null!==t&&rW(this.value)===rW(t)&&this.matchesComparison(rX(t,this.value))}matchesComparison(e){switch(this.op){case"<":return e<0;case"<=":return e<=0;case"==":return 0===e;case"!=":return 0!==e;case">":return e>0;case">=":return e>=0;default:return nK()}}isInequality(){return["<","<=",">",">=","!=","not-in"].indexOf(this.op)>=0}getFlattenedFilters(){return[this]}getFilters(){return[this]}getFirstInequalityField(){return this.isInequality()?this.field:null}}class ia extends ii{constructor(e,t){super(),this.filters=e,this.op=t,this.ht=null}static create(e,t){return new ia(e,t)}matches(e){return io(this)?void 0===this.filters.find(t=>!t.matches(e)):void 0!==this.filters.find(t=>t.matches(e))}getFlattenedFilters(){return null!==this.ht||(this.ht=this.filters.reduce((e,t)=>e.concat(t.getFlattenedFilters()),[])),this.ht}getFilters(){return Object.assign([],this.filters)}getFirstInequalityField(){let e=this.lt(e=>e.isInequality());return null!==e?e.field:null}lt(e){for(let t of this.getFlattenedFilters())if(e(t))return t;return null}}function io(e){return"and"===e.op}function il(e){return"or"===e.op}function iu(e){for(let t of e.filters)if(t instanceof ia)return!1;return!0}function ic(e,t){let n=e.filters.concat(t);return ia.create(n,e.op)}class ih extends is{constructor(e,t,n){super(e,t,n),this.key=ri.fromName(n.referenceValue)}matches(e){let t=ri.comparator(e.key,this.key);return this.matchesComparison(t)}}class id extends is{constructor(e,t){super(e,"in",t),this.keys=im("in",t)}matches(e){return this.keys.some(t=>t.isEqual(e.key))}}class ip extends is{constructor(e,t){super(e,"not-in",t),this.keys=im("not-in",t)}matches(e){return!this.keys.some(t=>t.isEqual(e.key))}}function im(e,t){var n;return((null===(n=t.arrayValue)||void 0===n?void 0:n.values)||[]).map(e=>ri.fromName(e.referenceValue))}class ig extends is{constructor(e,t){super(e,"array-contains",t)}matches(e){let t=e.data.field(this.field);return r2(t)&&rY(t.arrayValue,this.value)}}class iy extends is{constructor(e,t){super(e,"in",t)}matches(e){let t=e.data.field(this.field);return null!==t&&rY(this.value.arrayValue,t)}}class iv extends is{constructor(e,t){super(e,"not-in",t)}matches(e){if(rY(this.value.arrayValue,{nullValue:"NULL_VALUE"}))return!1;let t=e.data.field(this.field);return null!==t&&!rY(this.value.arrayValue,t)}}class iw extends is{constructor(e,t){super(e,"array-contains-any",t)}matches(e){let t=e.data.field(this.field);return!(!r2(t)||!t.arrayValue.values)&&t.arrayValue.values.some(e=>rY(this.value.arrayValue,e))}}/**
 * @license
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class i_{constructor(e,t="asc"){this.field=e,this.dir=t}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class ib{constructor(e,t){this.comparator=e,this.root=t||iT.EMPTY}insert(e,t){return new ib(this.comparator,this.root.insert(e,t,this.comparator).copy(null,null,iT.BLACK,null,null))}remove(e){return new ib(this.comparator,this.root.remove(e,this.comparator).copy(null,null,iT.BLACK,null,null))}get(e){let t=this.root;for(;!t.isEmpty();){let n=this.comparator(e,t.key);if(0===n)return t.value;n<0?t=t.left:n>0&&(t=t.right)}return null}indexOf(e){let t=0,n=this.root;for(;!n.isEmpty();){let r=this.comparator(e,n.key);if(0===r)return t+n.left.size;r<0?n=n.left:(t+=n.left.size+1,n=n.right)}return -1}isEmpty(){return this.root.isEmpty()}get size(){return this.root.size}minKey(){return this.root.minKey()}maxKey(){return this.root.maxKey()}inorderTraversal(e){return this.root.inorderTraversal(e)}forEach(e){this.inorderTraversal((t,n)=>(e(t,n),!1))}toString(){let e=[];return this.inorderTraversal((t,n)=>(e.push(`${t}:${n}`),!1)),`{${e.join(", ")}}`}reverseTraversal(e){return this.root.reverseTraversal(e)}getIterator(){return new iI(this.root,null,this.comparator,!1)}getIteratorFrom(e){return new iI(this.root,e,this.comparator,!1)}getReverseIterator(){return new iI(this.root,null,this.comparator,!0)}getReverseIteratorFrom(e){return new iI(this.root,e,this.comparator,!0)}}class iI{constructor(e,t,n,r){this.isReverse=r,this.nodeStack=[];let i=1;for(;!e.isEmpty();)if(i=t?n(e.key,t):1,t&&r&&(i*=-1),i<0)e=this.isReverse?e.left:e.right;else{if(0===i){this.nodeStack.push(e);break}this.nodeStack.push(e),e=this.isReverse?e.right:e.left}}getNext(){let e=this.nodeStack.pop(),t={key:e.key,value:e.value};if(this.isReverse)for(e=e.left;!e.isEmpty();)this.nodeStack.push(e),e=e.right;else for(e=e.right;!e.isEmpty();)this.nodeStack.push(e),e=e.left;return t}hasNext(){return this.nodeStack.length>0}peek(){if(0===this.nodeStack.length)return null;let e=this.nodeStack[this.nodeStack.length-1];return{key:e.key,value:e.value}}}class iT{constructor(e,t,n,r,i){this.key=e,this.value=t,this.color=null!=n?n:iT.RED,this.left=null!=r?r:iT.EMPTY,this.right=null!=i?i:iT.EMPTY,this.size=this.left.size+1+this.right.size}copy(e,t,n,r,i){return new iT(null!=e?e:this.key,null!=t?t:this.value,null!=n?n:this.color,null!=r?r:this.left,null!=i?i:this.right)}isEmpty(){return!1}inorderTraversal(e){return this.left.inorderTraversal(e)||e(this.key,this.value)||this.right.inorderTraversal(e)}reverseTraversal(e){return this.right.reverseTraversal(e)||e(this.key,this.value)||this.left.reverseTraversal(e)}min(){return this.left.isEmpty()?this:this.left.min()}minKey(){return this.min().key}maxKey(){return this.right.isEmpty()?this.key:this.right.maxKey()}insert(e,t,n){let r=this,i=n(e,r.key);return(r=i<0?r.copy(null,null,null,r.left.insert(e,t,n),null):0===i?r.copy(null,t,null,null,null):r.copy(null,null,null,null,r.right.insert(e,t,n))).fixUp()}removeMin(){if(this.left.isEmpty())return iT.EMPTY;let e=this;return e.left.isRed()||e.left.left.isRed()||(e=e.moveRedLeft()),(e=e.copy(null,null,null,e.left.removeMin(),null)).fixUp()}remove(e,t){let n,r=this;if(0>t(e,r.key))r.left.isEmpty()||r.left.isRed()||r.left.left.isRed()||(r=r.moveRedLeft()),r=r.copy(null,null,null,r.left.remove(e,t),null);else{if(r.left.isRed()&&(r=r.rotateRight()),r.right.isEmpty()||r.right.isRed()||r.right.left.isRed()||(r=r.moveRedRight()),0===t(e,r.key)){if(r.right.isEmpty())return iT.EMPTY;n=r.right.min(),r=r.copy(n.key,n.value,null,null,r.right.removeMin())}r=r.copy(null,null,null,null,r.right.remove(e,t))}return r.fixUp()}isRed(){return this.color}fixUp(){let e=this;return e.right.isRed()&&!e.left.isRed()&&(e=e.rotateLeft()),e.left.isRed()&&e.left.left.isRed()&&(e=e.rotateRight()),e.left.isRed()&&e.right.isRed()&&(e=e.colorFlip()),e}moveRedLeft(){let e=this.colorFlip();return e.right.left.isRed()&&(e=(e=(e=e.copy(null,null,null,null,e.right.rotateRight())).rotateLeft()).colorFlip()),e}moveRedRight(){let e=this.colorFlip();return e.left.left.isRed()&&(e=(e=e.rotateRight()).colorFlip()),e}rotateLeft(){let e=this.copy(null,null,iT.RED,null,this.right.left);return this.right.copy(null,null,this.color,e,null)}rotateRight(){let e=this.copy(null,null,iT.RED,this.left.right,null);return this.left.copy(null,null,this.color,null,e)}colorFlip(){let e=this.left.copy(null,null,!this.left.color,null,null),t=this.right.copy(null,null,!this.right.color,null,null);return this.copy(null,null,!this.color,e,t)}checkMaxDepth(){let e=this.check();return Math.pow(2,e)<=this.size+1}check(){if(this.isRed()&&this.left.isRed()||this.right.isRed())throw nK();let e=this.left.check();if(e!==this.right.check())throw nK();return e+(this.isRed()?0:1)}}iT.EMPTY=null,iT.RED=!0,iT.BLACK=!1,iT.EMPTY=new class{constructor(){this.size=0}get key(){throw nK()}get value(){throw nK()}get color(){throw nK()}get left(){throw nK()}get right(){throw nK()}copy(e,t,n,r,i){return this}insert(e,t,n){return new iT(e,t)}remove(e,t){return this}isEmpty(){return!0}inorderTraversal(e){return!1}reverseTraversal(e){return!1}minKey(){return null}maxKey(){return null}isRed(){return!1}checkMaxDepth(){return!0}check(){return 0}};/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class iE{constructor(e){this.comparator=e,this.data=new ib(this.comparator)}has(e){return null!==this.data.get(e)}first(){return this.data.minKey()}last(){return this.data.maxKey()}get size(){return this.data.size}indexOf(e){return this.data.indexOf(e)}forEach(e){this.data.inorderTraversal((t,n)=>(e(t),!1))}forEachInRange(e,t){let n=this.data.getIteratorFrom(e[0]);for(;n.hasNext();){let r=n.getNext();if(this.comparator(r.key,e[1])>=0)return;t(r.key)}}forEachWhile(e,t){let n;for(n=void 0!==t?this.data.getIteratorFrom(t):this.data.getIterator();n.hasNext();)if(!e(n.getNext().key))return}firstAfterOrEqual(e){let t=this.data.getIteratorFrom(e);return t.hasNext()?t.getNext().key:null}getIterator(){return new iS(this.data.getIterator())}getIteratorFrom(e){return new iS(this.data.getIteratorFrom(e))}add(e){return this.copy(this.data.remove(e).insert(e,!0))}delete(e){return this.has(e)?this.copy(this.data.remove(e)):this}isEmpty(){return this.data.isEmpty()}unionWith(e){let t=this;return t.size<e.size&&(t=e,e=this),e.forEach(e=>{t=t.add(e)}),t}isEqual(e){if(!(e instanceof iE)||this.size!==e.size)return!1;let t=this.data.getIterator(),n=e.data.getIterator();for(;t.hasNext();){let r=t.getNext().key,i=n.getNext().key;if(0!==this.comparator(r,i))return!1}return!0}toArray(){let e=[];return this.forEach(t=>{e.push(t)}),e}toString(){let e=[];return this.forEach(t=>e.push(t)),"SortedSet("+e.toString()+")"}copy(e){let t=new iE(this.comparator);return t.data=e,t}}class iS{constructor(e){this.iter=e}getNext(){return this.iter.getNext().key}hasNext(){return this.iter.hasNext()}}function ik(e){return e.hasNext()?e.getNext():void 0}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class iA{constructor(e){this.fields=e,e.sort(rr.comparator)}static empty(){return new iA([])}unionWith(e){let t=new iE(rr.comparator);for(let n of this.fields)t=t.add(n);for(let r of e)t=t.add(r);return new iA(t.toArray())}covers(e){for(let t of this.fields)if(t.isPrefixOf(e))return!0;return!1}isEqual(e){return n9(this.fields,e.fields,(e,t)=>e.isEqual(t))}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class iC{constructor(e){this.value=e}static empty(){return new iC({mapValue:{}})}field(e){if(e.isEmpty())return this.value;{let t=this.value;for(let n=0;n<e.length-1;++n)if(!r6(t=(t.mapValue.fields||{})[e.get(n)]))return null;return(t=(t.mapValue.fields||{})[e.lastSegment()])||null}}set(e,t){this.getFieldsMap(e.popLast())[e.lastSegment()]=r5(t)}setAll(e){let t=rr.emptyPath(),n={},r=[];e.forEach((e,i)=>{if(!t.isImmediateParentOf(i)){let s=this.getFieldsMap(t);this.applyChanges(s,n,r),n={},r=[],t=i.popLast()}e?n[i.lastSegment()]=r5(e):r.push(i.lastSegment())});let i=this.getFieldsMap(t);this.applyChanges(i,n,r)}delete(e){let t=this.field(e.popLast());r6(t)&&t.mapValue.fields&&delete t.mapValue.fields[e.lastSegment()]}isEqual(e){return rQ(this.value,e.value)}getFieldsMap(e){let t=this.value;t.mapValue.fields||(t.mapValue={fields:{}});for(let n=0;n<e.length;++n){let r=t.mapValue.fields[e.get(n)];r6(r)&&r.mapValue.fields||(r={mapValue:{fields:{}}},t.mapValue.fields[e.get(n)]=r),t=r}return t.mapValue.fields}applyChanges(e,t,n){for(let r of(rO(t,(t,n)=>e[t]=n),n))delete e[r]}clone(){return new iC(r5(this.value))}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class ix{constructor(e,t,n,r,i,s,a){this.key=e,this.documentType=t,this.version=n,this.readTime=r,this.createTime=i,this.data=s,this.documentState=a}static newInvalidDocument(e){return new ix(e,0,n7.min(),n7.min(),n7.min(),iC.empty(),0)}static newFoundDocument(e,t,n,r){return new ix(e,1,t,n7.min(),n,r,0)}static newNoDocument(e,t){return new ix(e,2,t,n7.min(),n7.min(),iC.empty(),0)}static newUnknownDocument(e,t){return new ix(e,3,t,n7.min(),n7.min(),iC.empty(),2)}convertToFoundDocument(e,t){return this.createTime.isEqual(n7.min())&&(2===this.documentType||0===this.documentType)&&(this.createTime=e),this.version=e,this.documentType=1,this.data=t,this.documentState=0,this}convertToNoDocument(e){return this.version=e,this.documentType=2,this.data=iC.empty(),this.documentState=0,this}convertToUnknownDocument(e){return this.version=e,this.documentType=3,this.data=iC.empty(),this.documentState=2,this}setHasCommittedMutations(){return this.documentState=2,this}setHasLocalMutations(){return this.documentState=1,this.version=n7.min(),this}setReadTime(e){return this.readTime=e,this}get hasLocalMutations(){return 1===this.documentState}get hasCommittedMutations(){return 2===this.documentState}get hasPendingWrites(){return this.hasLocalMutations||this.hasCommittedMutations}isValidDocument(){return 0!==this.documentType}isFoundDocument(){return 1===this.documentType}isNoDocument(){return 2===this.documentType}isUnknownDocument(){return 3===this.documentType}isEqual(e){return e instanceof ix&&this.key.isEqual(e.key)&&this.version.isEqual(e.version)&&this.documentType===e.documentType&&this.documentState===e.documentState&&this.data.isEqual(e.data)}mutableCopy(){return new ix(this.key,this.documentType,this.version,this.readTime,this.createTime,this.data.clone(),this.documentState)}toString(){return`Document(${this.key}, ${this.version}, ${JSON.stringify(this.data.value)}, {createTime: ${this.createTime}}), {documentType: ${this.documentType}}), {documentState: ${this.documentState}})`}}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class iR{constructor(e,t=null,n=[],r=[],i=null,s=null,a=null){this.path=e,this.collectionGroup=t,this.orderBy=n,this.filters=r,this.limit=i,this.startAt=s,this.endAt=a,this.ft=null}}function iD(e,t=null,n=[],r=[],i=null,s=null,a=null){return new iR(e,t,n,r,i,s,a)}function iN(e){let t=e;if(null===t.ft){let n=t.path.canonicalString();null!==t.collectionGroup&&(n+="|cg:"+t.collectionGroup),n+="|f:"+t.filters.map(e=>(function e(t){if(t instanceof is)return t.field.canonicalString()+t.op.toString()+rZ(t.value);{let n=t.filters.map(t=>e(t)).join(",");return`${t.op}(${n})`}})(e)).join(",")+"|ob:"+t.orderBy.map(e=>e.field.canonicalString()+e.dir).join(","),rL(t.limit)||(n+="|l:"+t.limit),t.startAt&&(n+="|lb:"+(t.startAt.inclusive?"b:":"a:")+t.startAt.position.map(e=>rZ(e)).join(",")),t.endAt&&(n+="|ub:"+(t.endAt.inclusive?"a:":"b:")+t.endAt.position.map(e=>rZ(e)).join(",")),t.ft=n}return t.ft}function iO(e,t){if(e.limit!==t.limit||e.orderBy.length!==t.orderBy.length)return!1;for(let n=0;n<e.orderBy.length;n++){var r,i;if(r=e.orderBy[n],i=t.orderBy[n],!(r.dir===i.dir&&r.field.isEqual(i.field)))return!1}if(e.filters.length!==t.filters.length)return!1;for(let s=0;s<e.filters.length;s++)if(!function e(t,n){return t instanceof is?n instanceof is&&t.op===n.op&&t.field.isEqual(n.field)&&rQ(t.value,n.value):t instanceof ia?n instanceof ia&&t.op===n.op&&t.filters.length===n.filters.length&&t.filters.reduce((t,r,i)=>t&&e(r,n.filters[i]),!0):void nK()}(e.filters[s],t.filters[s]))return!1;return e.collectionGroup===t.collectionGroup&&!!e.path.isEqual(t.path)&&!!ir(e.startAt,t.startAt)&&ir(e.endAt,t.endAt)}function iP(e){return ri.isDocumentKey(e.path)&&null===e.collectionGroup&&0===e.filters.length}function iL(e,t){return e.filters.filter(e=>e instanceof is&&e.field.isEqual(t))}function iM(e,t,n){let r=rH,i=!0;for(let s of iL(e,t)){let a=rH,o=!0;switch(s.op){case"<":case"<=":var l;a="nullValue"in(l=s.value)?rH:"booleanValue"in l?{booleanValue:!1}:"integerValue"in l||"doubleValue"in l?{doubleValue:NaN}:"timestampValue"in l?{timestampValue:{seconds:Number.MIN_SAFE_INTEGER}}:"stringValue"in l?{stringValue:""}:"bytesValue"in l?{bytesValue:""}:"referenceValue"in l?r0(rD.empty(),ri.empty()):"geoPointValue"in l?{geoPointValue:{latitude:-90,longitude:-180}}:"arrayValue"in l?{arrayValue:{}}:"mapValue"in l?{mapValue:{}}:nK();break;case"==":case"in":case">=":a=s.value;break;case">":a=s.value,o=!1;break;case"!=":case"not-in":a=rH}0>r8({value:r,inclusive:i},{value:a,inclusive:o})&&(r=a,i=o)}if(null!==n){for(let u=0;u<e.orderBy.length;++u)if(e.orderBy[u].field.isEqual(t)){let c=n.position[u];0>r8({value:r,inclusive:i},{value:c,inclusive:n.inclusive})&&(r=c,i=n.inclusive);break}}return{value:r,inclusive:i}}function iF(e,t,n){let r=rK,i=!0;for(let s of iL(e,t)){let a=rK,o=!0;switch(s.op){case">=":case">":var l;a="nullValue"in(l=s.value)?{booleanValue:!1}:"booleanValue"in l?{doubleValue:NaN}:"integerValue"in l||"doubleValue"in l?{timestampValue:{seconds:Number.MIN_SAFE_INTEGER}}:"timestampValue"in l?{stringValue:""}:"stringValue"in l?{bytesValue:""}:"bytesValue"in l?r0(rD.empty(),ri.empty()):"referenceValue"in l?{geoPointValue:{latitude:-90,longitude:-180}}:"geoPointValue"in l?{arrayValue:{}}:"arrayValue"in l?{mapValue:{}}:"mapValue"in l?rK:nK(),o=!1;break;case"==":case"in":case"<=":a=s.value;break;case"<":a=s.value,o=!1;break;case"!=":case"not-in":a=rK}r7({value:r,inclusive:i},{value:a,inclusive:o})>0&&(r=a,i=o)}if(null!==n){for(let u=0;u<e.orderBy.length;++u)if(e.orderBy[u].field.isEqual(t)){let c=n.position[u];r7({value:r,inclusive:i},{value:c,inclusive:n.inclusive})>0&&(r=c,i=n.inclusive);break}}return{value:r,inclusive:i}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class iU{constructor(e,t=null,n=[],r=[],i=null,s="F",a=null,o=null){this.path=e,this.collectionGroup=t,this.explicitOrderBy=n,this.filters=r,this.limit=i,this.limitType=s,this.startAt=a,this.endAt=o,this.dt=null,this._t=null,this.startAt,this.endAt}}function iV(e){return new iU(e)}function iq(e){return 0===e.filters.length&&null===e.limit&&null==e.startAt&&null==e.endAt&&(0===e.explicitOrderBy.length||1===e.explicitOrderBy.length&&e.explicitOrderBy[0].field.isKeyField())}function iB(e){return e.explicitOrderBy.length>0?e.explicitOrderBy[0].field:null}function ij(e){for(let t of e.filters){let n=t.getFirstInequalityField();if(null!==n)return n}return null}function i$(e){return null!==e.collectionGroup}function iz(e){let t=e;if(null===t.dt){t.dt=[];let n=ij(t),r=iB(t);if(null!==n&&null===r)n.isKeyField()||t.dt.push(new i_(n)),t.dt.push(new i_(rr.keyField(),"asc"));else{let i=!1;for(let s of t.explicitOrderBy)t.dt.push(s),s.field.isKeyField()&&(i=!0);if(!i){let a=t.explicitOrderBy.length>0?t.explicitOrderBy[t.explicitOrderBy.length-1].dir:"asc";t.dt.push(new i_(rr.keyField(),a))}}}return t.dt}function iG(e){let t=e;if(!t._t){if("F"===t.limitType)t._t=iD(t.path,t.collectionGroup,iz(t),t.filters,t.limit,t.startAt,t.endAt);else{let n=[];for(let r of iz(t)){let i="desc"===r.dir?"asc":"desc";n.push(new i_(r.field,i))}let s=t.endAt?new ie(t.endAt.position,t.endAt.inclusive):null,a=t.startAt?new ie(t.startAt.position,t.startAt.inclusive):null;t._t=iD(t.path,t.collectionGroup,n,t.filters,t.limit,s,a)}}return t._t}function iK(e,t){t.getFirstInequalityField(),ij(e);let n=e.filters.concat([t]);return new iU(e.path,e.collectionGroup,e.explicitOrderBy.slice(),n,e.limit,e.limitType,e.startAt,e.endAt)}function iH(e,t,n){return new iU(e.path,e.collectionGroup,e.explicitOrderBy.slice(),e.filters.slice(),t,n,e.startAt,e.endAt)}function iW(e,t){return iO(iG(e),iG(t))&&e.limitType===t.limitType}function iQ(e){return`${iN(iG(e))}|lt:${e.limitType}`}function iY(e){var t;let n;return`Query(target=${n=(t=iG(e)).path.canonicalString(),null!==t.collectionGroup&&(n+=" collectionGroup="+t.collectionGroup),t.filters.length>0&&(n+=`, filters: [${t.filters.map(e=>(function e(t){return t instanceof is?`${t.field.canonicalString()} ${t.op} ${rZ(t.value)}`:t instanceof ia?t.op.toString()+" {"+t.getFilters().map(e).join(" ,")+"}":"Filter"})(e)).join(", ")}]`),rL(t.limit)||(n+=", limit: "+t.limit),t.orderBy.length>0&&(n+=`, orderBy: [${t.orderBy.map(e=>`${e.field.canonicalString()} (${e.dir})`).join(", ")}]`),t.startAt&&(n+=", startAt: "+(t.startAt.inclusive?"b:":"a:")+t.startAt.position.map(e=>rZ(e)).join(",")),t.endAt&&(n+=", endAt: "+(t.endAt.inclusive?"a:":"b:")+t.endAt.position.map(e=>rZ(e)).join(",")),`Target(${n})`}; limitType=${e.limitType})`}function iX(e,t){return t.isFoundDocument()&&function(e,t){let n=t.key.path;return null!==e.collectionGroup?t.key.hasCollectionId(e.collectionGroup)&&e.path.isPrefixOf(n):ri.isDocumentKey(e.path)?e.path.isEqual(n):e.path.isImmediateParentOf(n)}(e,t)&&function(e,t){for(let n of iz(e))if(!n.field.isKeyField()&&null===t.data.field(n.field))return!1;return!0}(e,t)&&function(e,t){for(let n of e.filters)if(!n.matches(t))return!1;return!0}(e,t)&&(!e.startAt||!!function(e,t,n){let r=it(e,t,n);return e.inclusive?r<=0:r<0}(e.startAt,iz(e),t))&&(!e.endAt||!!function(e,t,n){let r=it(e,t,n);return e.inclusive?r>=0:r>0}(e.endAt,iz(e),t))}function iJ(e){return e.collectionGroup||(e.path.length%2==1?e.path.lastSegment():e.path.get(e.path.length-2))}function iZ(e){return(t,n)=>{let r=!1;for(let i of iz(e)){let s=function(e,t,n){let r=e.field.isKeyField()?ri.comparator(t.key,n.key):function(e,t,n){let r=t.data.field(e),i=n.data.field(e);return null!==r&&null!==i?rX(r,i):nK()}(e.field,t,n);switch(e.dir){case"asc":return r;case"desc":return -1*r;default:return nK()}}(i,t,n);if(0!==s)return s;r=r||i.field.isKeyField()}return 0}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function i0(e,t){if(e.wt){if(isNaN(t))return{doubleValue:"NaN"};if(t===1/0)return{doubleValue:"Infinity"};if(t===-1/0)return{doubleValue:"-Infinity"}}return{doubleValue:rM(t)?"-0":t}}function i1(e){return{integerValue:""+e}}function i2(e,t){return rF(t)?i1(t):i0(e,t)}/**
 * @license
 * Copyright 2018 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class i4{constructor(){this._=void 0}}function i3(e,t){return e instanceof se?r1(t)||t&&"doubleValue"in t?t:{integerValue:0}:null}class i6 extends i4{}class i5 extends i4{constructor(e){super(),this.elements=e}}function i9(e,t){let n=sn(t);for(let r of e.elements)n.some(e=>rQ(e,r))||n.push(r);return{arrayValue:{values:n}}}class i8 extends i4{constructor(e){super(),this.elements=e}}function i7(e,t){let n=sn(t);for(let r of e.elements)n=n.filter(e=>!rQ(e,r));return{arrayValue:{values:n}}}class se extends i4{constructor(e,t){super(),this.yt=e,this.gt=t}}function st(e){return rj(e.integerValue||e.doubleValue)}function sn(e){return r2(e)&&e.arrayValue.values?e.arrayValue.values.slice():[]}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class sr{constructor(e,t){this.field=e,this.transform=t}}class si{constructor(e,t){this.version=e,this.transformResults=t}}class ss{constructor(e,t){this.updateTime=e,this.exists=t}static none(){return new ss}static exists(e){return new ss(void 0,e)}static updateTime(e){return new ss(e)}get isNone(){return void 0===this.updateTime&&void 0===this.exists}isEqual(e){return this.exists===e.exists&&(this.updateTime?!!e.updateTime&&this.updateTime.isEqual(e.updateTime):!e.updateTime)}}function sa(e,t){return void 0!==e.updateTime?t.isFoundDocument()&&t.version.isEqual(e.updateTime):void 0===e.exists||e.exists===t.isFoundDocument()}class so{}function sl(e,t){if(!e.hasLocalMutations||t&&0===t.fields.length)return null;if(null===t)return e.isNoDocument()?new sg(e.key,ss.none()):new sh(e.key,e.data,ss.none());{let n=e.data,r=iC.empty(),i=new iE(rr.comparator);for(let s of t.fields)if(!i.has(s)){let a=n.field(s);null===a&&s.length>1&&(s=s.popLast(),a=n.field(s)),null===a?r.delete(s):r.set(s,a),i=i.add(s)}return new sd(e.key,r,new iA(i.toArray()),ss.none())}}function su(e,t,n,r){return e instanceof sh?function(e,t,n,r){if(!sa(e.precondition,t))return n;let i=e.value.clone(),s=sm(e.fieldTransforms,r,t);return i.setAll(s),t.convertToFoundDocument(t.version,i).setHasLocalMutations(),null}(e,t,n,r):e instanceof sd?function(e,t,n,r){if(!sa(e.precondition,t))return n;let i=sm(e.fieldTransforms,r,t),s=t.data;return(s.setAll(sf(e)),s.setAll(i),t.convertToFoundDocument(t.version,s).setHasLocalMutations(),null===n)?null:n.unionWith(e.fieldMask.fields).unionWith(e.fieldTransforms.map(e=>e.field))}(e,t,n,r):sa(e.precondition,t)?(t.convertToNoDocument(t.version).setHasLocalMutations(),null):n}function sc(e,t){var n,r;return e.type===t.type&&!!e.key.isEqual(t.key)&&!!e.precondition.isEqual(t.precondition)&&(n=e.fieldTransforms,r=t.fieldTransforms,!!(void 0===n&&void 0===r||!(!n||!r)&&n9(n,r,(e,t)=>{var n,r;return e.field.isEqual(t.field)&&(n=e.transform,r=t.transform,n instanceof i5&&r instanceof i5||n instanceof i8&&r instanceof i8?n9(n.elements,r.elements,rQ):n instanceof se&&r instanceof se?rQ(n.gt,r.gt):n instanceof i6&&r instanceof i6)})))&&(0===e.type?e.value.isEqual(t.value):1!==e.type||e.data.isEqual(t.data)&&e.fieldMask.isEqual(t.fieldMask))}class sh extends so{constructor(e,t,n,r=[]){super(),this.key=e,this.value=t,this.precondition=n,this.fieldTransforms=r,this.type=0}getFieldMask(){return null}}class sd extends so{constructor(e,t,n,r,i=[]){super(),this.key=e,this.data=t,this.fieldMask=n,this.precondition=r,this.fieldTransforms=i,this.type=1}getFieldMask(){return this.fieldMask}}function sf(e){let t=new Map;return e.fieldMask.fields.forEach(n=>{if(!n.isEmpty()){let r=e.data.field(n);t.set(n,r)}}),t}function sp(e,t,n){var r;let i=new Map;e.length===n.length||nK();for(let s=0;s<n.length;s++){let a=e[s],o=a.transform,l=t.data.field(a.field);i.set(a.field,(r=n[s],o instanceof i5?i9(o,l):o instanceof i8?i7(o,l):r))}return i}function sm(e,t,n){let r=new Map;for(let i of e){let s=i.transform,a=n.data.field(i.field);r.set(i.field,s instanceof i6?function(e,t){let n={fields:{__type__:{stringValue:"server_timestamp"},__local_write_time__:{timestampValue:{seconds:e.seconds,nanos:e.nanoseconds}}}};return t&&(n.fields.__previous_value__=t),{mapValue:n}}(t,a):s instanceof i5?i9(s,a):s instanceof i8?i7(s,a):function(e,t){let n=i3(e,t),r=st(n)+st(e.gt);return r1(n)&&r1(e.gt)?i1(r):i0(e.yt,r)}(s,a))}return r}class sg extends so{constructor(e,t){super(),this.key=e,this.precondition=t,this.type=2,this.fieldTransforms=[]}getFieldMask(){return null}}class sy extends so{constructor(e,t){super(),this.key=e,this.precondition=t,this.type=3,this.fieldTransforms=[]}getFieldMask(){return null}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class sv{constructor(e){this.count=e}}function sw(e){switch(e){default:return nK();case nW.CANCELLED:case nW.UNKNOWN:case nW.DEADLINE_EXCEEDED:case nW.RESOURCE_EXHAUSTED:case nW.INTERNAL:case nW.UNAVAILABLE:case nW.UNAUTHENTICATED:return!1;case nW.INVALID_ARGUMENT:case nW.NOT_FOUND:case nW.ALREADY_EXISTS:case nW.PERMISSION_DENIED:case nW.FAILED_PRECONDITION:case nW.ABORTED:case nW.OUT_OF_RANGE:case nW.UNIMPLEMENTED:case nW.DATA_LOSS:return!0}}function s_(e){if(void 0===e)return n$("GRPC error has no .code"),nW.UNKNOWN;switch(e){case l.OK:return nW.OK;case l.CANCELLED:return nW.CANCELLED;case l.UNKNOWN:return nW.UNKNOWN;case l.DEADLINE_EXCEEDED:return nW.DEADLINE_EXCEEDED;case l.RESOURCE_EXHAUSTED:return nW.RESOURCE_EXHAUSTED;case l.INTERNAL:return nW.INTERNAL;case l.UNAVAILABLE:return nW.UNAVAILABLE;case l.UNAUTHENTICATED:return nW.UNAUTHENTICATED;case l.INVALID_ARGUMENT:return nW.INVALID_ARGUMENT;case l.NOT_FOUND:return nW.NOT_FOUND;case l.ALREADY_EXISTS:return nW.ALREADY_EXISTS;case l.PERMISSION_DENIED:return nW.PERMISSION_DENIED;case l.FAILED_PRECONDITION:return nW.FAILED_PRECONDITION;case l.ABORTED:return nW.ABORTED;case l.OUT_OF_RANGE:return nW.OUT_OF_RANGE;case l.UNIMPLEMENTED:return nW.UNIMPLEMENTED;case l.DATA_LOSS:return nW.DATA_LOSS;default:return nK()}}(u=l||(l={}))[u.OK=0]="OK",u[u.CANCELLED=1]="CANCELLED",u[u.UNKNOWN=2]="UNKNOWN",u[u.INVALID_ARGUMENT=3]="INVALID_ARGUMENT",u[u.DEADLINE_EXCEEDED=4]="DEADLINE_EXCEEDED",u[u.NOT_FOUND=5]="NOT_FOUND",u[u.ALREADY_EXISTS=6]="ALREADY_EXISTS",u[u.PERMISSION_DENIED=7]="PERMISSION_DENIED",u[u.UNAUTHENTICATED=16]="UNAUTHENTICATED",u[u.RESOURCE_EXHAUSTED=8]="RESOURCE_EXHAUSTED",u[u.FAILED_PRECONDITION=9]="FAILED_PRECONDITION",u[u.ABORTED=10]="ABORTED",u[u.OUT_OF_RANGE=11]="OUT_OF_RANGE",u[u.UNIMPLEMENTED=12]="UNIMPLEMENTED",u[u.INTERNAL=13]="INTERNAL",u[u.UNAVAILABLE=14]="UNAVAILABLE",u[u.DATA_LOSS=15]="DATA_LOSS";/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class sb{constructor(e,t){this.mapKeyFn=e,this.equalsFn=t,this.inner={},this.innerSize=0}get(e){let t=this.mapKeyFn(e),n=this.inner[t];if(void 0!==n){for(let[r,i]of n)if(this.equalsFn(r,e))return i}}has(e){return void 0!==this.get(e)}set(e,t){let n=this.mapKeyFn(e),r=this.inner[n];if(void 0===r)return this.inner[n]=[[e,t]],void this.innerSize++;for(let i=0;i<r.length;i++)if(this.equalsFn(r[i][0],e))return void(r[i]=[e,t]);r.push([e,t]),this.innerSize++}delete(e){let t=this.mapKeyFn(e),n=this.inner[t];if(void 0===n)return!1;for(let r=0;r<n.length;r++)if(this.equalsFn(n[r][0],e))return 1===n.length?delete this.inner[t]:n.splice(r,1),this.innerSize--,!0;return!1}forEach(e){rO(this.inner,(t,n)=>{for(let[r,i]of n)e(r,i)})}isEmpty(){return rP(this.inner)}size(){return this.innerSize}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let sI=new ib(ri.comparator),sT=new ib(ri.comparator);function sE(...e){let t=sT;for(let n of e)t=t.insert(n.key,n);return t}function sS(e){let t=sT;return e.forEach((e,n)=>t=t.insert(e,n.overlayedDocument)),t}function sk(){return new sb(e=>e.toString(),(e,t)=>e.isEqual(t))}let sA=new ib(ri.comparator),sC=new iE(ri.comparator);function sx(...e){let t=sC;for(let n of e)t=t.add(n);return t}let sR=new iE(n5);/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class sD{constructor(e,t,n,r,i){this.snapshotVersion=e,this.targetChanges=t,this.targetMismatches=n,this.documentUpdates=r,this.resolvedLimboDocuments=i}static createSynthesizedRemoteEventForCurrentChange(e,t,n){let r=new Map;return r.set(e,sN.createSynthesizedTargetChangeForCurrentChange(e,t,n)),new sD(n7.min(),r,sR,sI,sx())}}class sN{constructor(e,t,n,r,i){this.resumeToken=e,this.current=t,this.addedDocuments=n,this.modifiedDocuments=r,this.removedDocuments=i}static createSynthesizedTargetChangeForCurrentChange(e,t,n){return new sN(n,t,sx(),sx(),sx())}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class sO{constructor(e,t,n,r){this.It=e,this.removedTargetIds=t,this.key=n,this.Tt=r}}class sP{constructor(e,t){this.targetId=e,this.Et=t}}class sL{constructor(e,t,n=rV.EMPTY_BYTE_STRING,r=null){this.state=e,this.targetIds=t,this.resumeToken=n,this.cause=r}}class sM{constructor(){this.At=0,this.Rt=sV(),this.bt=rV.EMPTY_BYTE_STRING,this.Pt=!1,this.vt=!0}get current(){return this.Pt}get resumeToken(){return this.bt}get Vt(){return 0!==this.At}get St(){return this.vt}Dt(e){e.approximateByteSize()>0&&(this.vt=!0,this.bt=e)}Ct(){let e=sx(),t=sx(),n=sx();return this.Rt.forEach((r,i)=>{switch(i){case 0:e=e.add(r);break;case 2:t=t.add(r);break;case 1:n=n.add(r);break;default:nK()}}),new sN(this.bt,this.Pt,e,t,n)}xt(){this.vt=!1,this.Rt=sV()}Nt(e,t){this.vt=!0,this.Rt=this.Rt.insert(e,t)}kt(e){this.vt=!0,this.Rt=this.Rt.remove(e)}Ot(){this.At+=1}Mt(){this.At-=1}Ft(){this.vt=!0,this.Pt=!0}}class sF{constructor(e){this.$t=e,this.Bt=new Map,this.Lt=sI,this.qt=sU(),this.Ut=new iE(n5)}Kt(e){for(let t of e.It)e.Tt&&e.Tt.isFoundDocument()?this.Gt(t,e.Tt):this.Qt(t,e.key,e.Tt);for(let n of e.removedTargetIds)this.Qt(n,e.key,e.Tt)}jt(e){this.forEachTarget(e,t=>{let n=this.Wt(t);switch(e.state){case 0:this.zt(t)&&n.Dt(e.resumeToken);break;case 1:n.Mt(),n.Vt||n.xt(),n.Dt(e.resumeToken);break;case 2:n.Mt(),n.Vt||this.removeTarget(t);break;case 3:this.zt(t)&&(n.Ft(),n.Dt(e.resumeToken));break;case 4:this.zt(t)&&(this.Ht(t),n.Dt(e.resumeToken));break;default:nK()}})}forEachTarget(e,t){e.targetIds.length>0?e.targetIds.forEach(t):this.Bt.forEach((e,n)=>{this.zt(n)&&t(n)})}Jt(e){let t=e.targetId,n=e.Et.count,r=this.Yt(t);if(r){let i=r.target;if(iP(i)){if(0===n){let s=new ri(i.path);this.Qt(t,s,ix.newNoDocument(s,n7.min()))}else 1===n||nK()}else this.Xt(t)!==n&&(this.Ht(t),this.Ut=this.Ut.add(t))}}Zt(e){let t=new Map;this.Bt.forEach((n,r)=>{let i=this.Yt(r);if(i){if(n.current&&iP(i.target)){let s=new ri(i.target.path);null!==this.Lt.get(s)||this.te(r,s)||this.Qt(r,s,ix.newNoDocument(s,e))}n.St&&(t.set(r,n.Ct()),n.xt())}});let n=sx();this.qt.forEach((e,t)=>{let r=!0;t.forEachWhile(e=>{let t=this.Yt(e);return!t||2===t.purpose||(r=!1,!1)}),r&&(n=n.add(e))}),this.Lt.forEach((t,n)=>n.setReadTime(e));let r=new sD(e,t,this.Ut,this.Lt,n);return this.Lt=sI,this.qt=sU(),this.Ut=new iE(n5),r}Gt(e,t){if(!this.zt(e))return;let n=this.te(e,t.key)?2:0;this.Wt(e).Nt(t.key,n),this.Lt=this.Lt.insert(t.key,t),this.qt=this.qt.insert(t.key,this.ee(t.key).add(e))}Qt(e,t,n){if(!this.zt(e))return;let r=this.Wt(e);this.te(e,t)?r.Nt(t,1):r.kt(t),this.qt=this.qt.insert(t,this.ee(t).delete(e)),n&&(this.Lt=this.Lt.insert(t,n))}removeTarget(e){this.Bt.delete(e)}Xt(e){let t=this.Wt(e).Ct();return this.$t.getRemoteKeysForTarget(e).size+t.addedDocuments.size-t.removedDocuments.size}Ot(e){this.Wt(e).Ot()}Wt(e){let t=this.Bt.get(e);return t||(t=new sM,this.Bt.set(e,t)),t}ee(e){let t=this.qt.get(e);return t||(t=new iE(n5),this.qt=this.qt.insert(e,t)),t}zt(e){let t=null!==this.Yt(e);return t||nj("WatchChangeAggregator","Detected inactive target",e),t}Yt(e){let t=this.Bt.get(e);return t&&t.Vt?null:this.$t.ne(e)}Ht(e){this.Bt.set(e,new sM),this.$t.getRemoteKeysForTarget(e).forEach(t=>{this.Qt(e,t,null)})}te(e,t){return this.$t.getRemoteKeysForTarget(e).has(t)}}function sU(){return new ib(ri.comparator)}function sV(){return new ib(ri.comparator)}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let sq={asc:"ASCENDING",desc:"DESCENDING"},sB={"<":"LESS_THAN","<=":"LESS_THAN_OR_EQUAL",">":"GREATER_THAN",">=":"GREATER_THAN_OR_EQUAL","==":"EQUAL","!=":"NOT_EQUAL","array-contains":"ARRAY_CONTAINS",in:"IN","not-in":"NOT_IN","array-contains-any":"ARRAY_CONTAINS_ANY"},sj={and:"AND",or:"OR"};class s${constructor(e,t){this.databaseId=e,this.wt=t}}function sz(e,t){return e.wt?`${new Date(1e3*t.seconds).toISOString().replace(/\.\d*/,"").replace("Z","")}.${("000000000"+t.nanoseconds).slice(-9)}Z`:{seconds:""+t.seconds,nanos:t.nanoseconds}}function sG(e,t){return e.wt?t.toBase64():t.toUint8Array()}function sK(e){return e||nK(),n7.fromTimestamp(function(e){let t=rB(e);return new n8(t.seconds,t.nanos)}(e))}function sH(e,t){return new rt(["projects",e.projectId,"databases",e.database]).child("documents").child(t).canonicalString()}function sW(e){let t=rt.fromString(e);return ae(t)||nK(),t}function sQ(e,t){return sH(e.databaseId,t.path)}function sY(e,t){let n=sW(t);if(n.get(1)!==e.databaseId.projectId)throw new nQ(nW.INVALID_ARGUMENT,"Tried to deserialize key from different project: "+n.get(1)+" vs "+e.databaseId.projectId);if(n.get(3)!==e.databaseId.database)throw new nQ(nW.INVALID_ARGUMENT,"Tried to deserialize key from different database: "+n.get(3)+" vs "+e.databaseId.database);return new ri(s0(n))}function sX(e,t){return sH(e.databaseId,t)}function sJ(e){let t=sW(e);return 4===t.length?rt.emptyPath():s0(t)}function sZ(e){return new rt(["projects",e.databaseId.projectId,"databases",e.databaseId.database]).canonicalString()}function s0(e){return e.length>4&&"documents"===e.get(4)||nK(),e.popFirst(5)}function s1(e,t,n){return{name:sQ(e,t),fields:n.value.mapValue.fields}}function s2(e,t,n){let r=sY(e,t.name),i=sK(t.updateTime),s=t.createTime?sK(t.createTime):n7.min(),a=new iC({mapValue:{fields:t.fields}}),o=ix.newFoundDocument(r,i,s,a);return n&&o.setHasCommittedMutations(),n?o.setHasCommittedMutations():o}function s4(e,t){var n;let r;if(t instanceof sh)r={update:s1(e,t.key,t.value)};else if(t instanceof sg)r={delete:sQ(e,t.key)};else if(t instanceof sd)r={update:s1(e,t.key,t.data),updateMask:function(e){let t=[];return e.fields.forEach(e=>t.push(e.canonicalString())),{fieldPaths:t}}(t.fieldMask)};else{if(!(t instanceof sy))return nK();r={verify:sQ(e,t.key)}}return t.fieldTransforms.length>0&&(r.updateTransforms=t.fieldTransforms.map(e=>(function(e,t){let n=t.transform;if(n instanceof i6)return{fieldPath:t.field.canonicalString(),setToServerValue:"REQUEST_TIME"};if(n instanceof i5)return{fieldPath:t.field.canonicalString(),appendMissingElements:{values:n.elements}};if(n instanceof i8)return{fieldPath:t.field.canonicalString(),removeAllFromArray:{values:n.elements}};if(n instanceof se)return{fieldPath:t.field.canonicalString(),increment:n.gt};throw nK()})(0,e))),t.precondition.isNone||(r.currentDocument=void 0!==(n=t.precondition).updateTime?{updateTime:sz(e,n.updateTime.toTimestamp())}:void 0!==n.exists?{exists:n.exists}:nK()),r}function s3(e,t){var n;let r=t.currentDocument?void 0!==(n=t.currentDocument).updateTime?ss.updateTime(sK(n.updateTime)):void 0!==n.exists?ss.exists(n.exists):ss.none():ss.none(),i=t.updateTransforms?t.updateTransforms.map(t=>(function(e,t){let n=null;if("setToServerValue"in t)"REQUEST_TIME"===t.setToServerValue||nK(),n=new i6;else if("appendMissingElements"in t){let r=t.appendMissingElements.values||[];n=new i5(r)}else if("removeAllFromArray"in t){let i=t.removeAllFromArray.values||[];n=new i8(i)}else"increment"in t?n=new se(e,t.increment):nK();let s=rr.fromServerFormat(t.fieldPath);return new sr(s,n)})(e,t)):[];if(t.update){t.update.name;let s=sY(e,t.update.name),a=new iC({mapValue:{fields:t.update.fields}});if(t.updateMask){let o=function(e){let t=e.fieldPaths||[];return new iA(t.map(e=>rr.fromServerFormat(e)))}(t.updateMask);return new sd(s,a,o,r,i)}return new sh(s,a,r,i)}if(t.delete){let l=sY(e,t.delete);return new sg(l,r)}if(t.verify){let u=sY(e,t.verify);return new sy(u,r)}return nK()}function s6(e,t){return{documents:[sX(e,t.path)]}}function s5(e,t){var n,r,i;let s={structuredQuery:{}},a=t.path;null!==t.collectionGroup?(s.parent=sX(e,a),s.structuredQuery.from=[{collectionId:t.collectionGroup,allDescendants:!0}]):(s.parent=sX(e,a.popLast()),s.structuredQuery.from=[{collectionId:a.lastSegment()}]);let o=function(e){if(0!==e.length)return function e(t){return t instanceof is?function(e){if("=="===e.op){if(r3(e.value))return{unaryFilter:{field:s8(e.field),op:"IS_NAN"}};if(r4(e.value))return{unaryFilter:{field:s8(e.field),op:"IS_NULL"}}}else if("!="===e.op){if(r3(e.value))return{unaryFilter:{field:s8(e.field),op:"IS_NOT_NAN"}};if(r4(e.value))return{unaryFilter:{field:s8(e.field),op:"IS_NOT_NULL"}}}return{fieldFilter:{field:s8(e.field),op:sB[e.op],value:e.value}}}(t):t instanceof ia?function(t){let n=t.getFilters().map(t=>e(t));return 1===n.length?n[0]:{compositeFilter:{op:sj[t.op],filters:n}}}(t):nK()}(ia.create(e,"and"))}(t.filters);o&&(s.structuredQuery.where=o);let l=function(e){if(0!==e.length)return e.map(e=>({field:s8(e.field),direction:sq[e.dir]}))}(t.orderBy);l&&(s.structuredQuery.orderBy=l);let u=(r=t.limit,e.wt||rL(r)?r:{value:r});return null!==u&&(s.structuredQuery.limit=u),t.startAt&&(s.structuredQuery.startAt={before:(n=t.startAt).inclusive,values:n.position}),t.endAt&&(s.structuredQuery.endAt={before:!(i=t.endAt).inclusive,values:i.position}),s}function s9(e){var t,n,r,i,s,a,o,l;let u,c=sJ(e.parent),h=e.structuredQuery,d=h.from?h.from.length:0,f=null;if(d>0){1===d||nK();let p=h.from[0];p.allDescendants?f=p.collectionId:c=c.child(p.collectionId)}let m=[];h.where&&(m=function(e){var t;let n=function e(t){return void 0!==t.unaryFilter?function(e){switch(e.unaryFilter.op){case"IS_NAN":let t=s7(e.unaryFilter.field);return is.create(t,"==",{doubleValue:NaN});case"IS_NULL":let n=s7(e.unaryFilter.field);return is.create(n,"==",{nullValue:"NULL_VALUE"});case"IS_NOT_NAN":let r=s7(e.unaryFilter.field);return is.create(r,"!=",{doubleValue:NaN});case"IS_NOT_NULL":let i=s7(e.unaryFilter.field);return is.create(i,"!=",{nullValue:"NULL_VALUE"});default:return nK()}}(t):void 0!==t.fieldFilter?is.create(s7(t.fieldFilter.field),function(e){switch(e){case"EQUAL":return"==";case"NOT_EQUAL":return"!=";case"GREATER_THAN":return">";case"GREATER_THAN_OR_EQUAL":return">=";case"LESS_THAN":return"<";case"LESS_THAN_OR_EQUAL":return"<=";case"ARRAY_CONTAINS":return"array-contains";case"IN":return"in";case"NOT_IN":return"not-in";case"ARRAY_CONTAINS_ANY":return"array-contains-any";default:return nK()}}(t.fieldFilter.op),t.fieldFilter.value):void 0!==t.compositeFilter?ia.create(t.compositeFilter.filters.map(t=>e(t)),function(e){switch(e){case"AND":return"and";case"OR":return"or";default:return nK()}}(t.compositeFilter.op)):nK()}(e);return n instanceof ia&&iu(t=n)&&io(t)?n.getFilters():[n]}(h.where));let g=[];h.orderBy&&(g=h.orderBy.map(e=>new i_(s7(e.field),function(e){switch(e){case"ASCENDING":return"asc";case"DESCENDING":return"desc";default:return}}(e.direction))));let y=null;h.limit&&(y=rL(u="object"==typeof(t=h.limit)?t.value:t)?null:u);let v=null;h.startAt&&(v=function(e){let t=!!e.before,n=e.values||[];return new ie(n,t)}(h.startAt));let w=null;return h.endAt&&(w=function(e){let t=!e.before,n=e.values||[];return new ie(n,t)}(h.endAt)),n=c,r=f,i=g,s=m,a=y,o=v,l=w,new iU(n,r,i,s,a,"F",o,l)}function s8(e){return{fieldPath:e.canonicalString()}}function s7(e){return rr.fromServerFormat(e.fieldPath)}function ae(e){return e.length>=4&&"projects"===e.get(0)&&"databases"===e.get(2)}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function at(e){var t,n;let r="";for(let i=0;i<e.length;i++)r.length>0&&(r+="\x01\x01"),r=function(e,t){let n=t,r=e.length;for(let i=0;i<r;i++){let s=e.charAt(i);switch(s){case"\0":n+="\x01\x10";break;case"\x01":n+="\x01\x11";break;default:n+=s}}return n}(e.get(i),r);return r+"\x01\x01"}function an(e){let t=e.length;if(t>=2||nK(),2===t)return"\x01"===e.charAt(0)&&"\x01"===e.charAt(1)||nK(),rt.emptyPath();let n=t-2,r=[],i="";for(let s=0;s<t;){let a=e.indexOf("\x01",s);switch((a<0||a>n)&&nK(),e.charAt(a+1)){case"\x01":let o;let l=e.substring(s,a);0===i.length?o=l:(i+=l,o=i,i=""),r.push(o);break;case"\x10":i+=e.substring(s,a)+"\0";break;case"\x11":i+=e.substring(s,a+1);break;default:nK()}s=a+2}return new rt(r)}/**
 * @license
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let ar=["userId","batchId"],ai={},as=["prefixPath","collectionGroup","readTime","documentId"],aa=["prefixPath","collectionGroup","documentId"],ao=["collectionGroup","readTime","prefixPath","documentId"],al=["canonicalId","targetId"],au=["targetId","path"],ac=["path","targetId"],ah=["collectionId","parent"],ad=["indexId","uid"],af=["uid","sequenceNumber"],ap=["indexId","uid","arrayValue","directionalValue","orderedDocumentKey","documentKey"],am=["indexId","uid","orderedDocumentKey"],ag=["userId","collectionPath","documentId"],ay=["userId","collectionPath","largestBatchId"],av=["userId","collectionGroup","largestBatchId"],aw=["mutationQueues","mutations","documentMutations","remoteDocuments","targets","owner","targetGlobal","targetDocuments","clientMetadata","remoteDocumentGlobal","collectionParents","bundles","namedQueries"],a_=[...aw,"documentOverlays"],ab=["mutationQueues","mutations","documentMutations","remoteDocumentsV14","targets","owner","targetGlobal","targetDocuments","clientMetadata","remoteDocumentGlobal","collectionParents","bundles","namedQueries","documentOverlays"],aI=[...ab,"indexConfiguration","indexState","indexEntries"];/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class aT extends rm{constructor(e,t){super(),this.se=e,this.currentSequenceNumber=t}}function aE(e,t){return rw.M(e.se,t)}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class aS{constructor(e,t,n,r){this.batchId=e,this.localWriteTime=t,this.baseMutations=n,this.mutations=r}applyToRemoteDocument(e,t){let n=t.mutationResults;for(let r=0;r<this.mutations.length;r++){let i=this.mutations[r];if(i.key.isEqual(e.key)){var s;s=n[r],i instanceof sh?function(e,t,n){let r=e.value.clone(),i=sp(e.fieldTransforms,t,n.transformResults);r.setAll(i),t.convertToFoundDocument(n.version,r).setHasCommittedMutations()}(i,e,s):i instanceof sd?function(e,t,n){if(!sa(e.precondition,t))return void t.convertToUnknownDocument(n.version);let r=sp(e.fieldTransforms,t,n.transformResults),i=t.data;i.setAll(sf(e)),i.setAll(r),t.convertToFoundDocument(n.version,i).setHasCommittedMutations()}(i,e,s):function(e,t,n){t.convertToNoDocument(n.version).setHasCommittedMutations()}(0,e,s)}}}applyToLocalView(e,t){for(let n of this.baseMutations)n.key.isEqual(e.key)&&(t=su(n,e,t,this.localWriteTime));for(let r of this.mutations)r.key.isEqual(e.key)&&(t=su(r,e,t,this.localWriteTime));return t}applyToLocalDocumentSet(e,t){let n=sk();return this.mutations.forEach(r=>{let i=e.get(r.key),s=i.overlayedDocument,a=this.applyToLocalView(s,i.mutatedFields);a=t.has(r.key)?null:a;let o=sl(s,a);null!==o&&n.set(r.key,o),s.isValidDocument()||s.convertToNoDocument(n7.min())}),n}keys(){return this.mutations.reduce((e,t)=>e.add(t.key),sx())}isEqual(e){return this.batchId===e.batchId&&n9(this.mutations,e.mutations,(e,t)=>sc(e,t))&&n9(this.baseMutations,e.baseMutations,(e,t)=>sc(e,t))}}class ak{constructor(e,t,n,r){this.batch=e,this.commitVersion=t,this.mutationResults=n,this.docVersions=r}static from(e,t,n){e.mutations.length===n.length||nK();let r=sA,i=e.mutations;for(let s=0;s<i.length;s++)r=r.insert(i[s].key,n[s].version);return new ak(e,t,n,r)}}/**
 * @license
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class aA{constructor(e,t){this.largestBatchId=e,this.mutation=t}getKey(){return this.mutation.key}isEqual(e){return null!==e&&this.mutation===e.mutation}toString(){return`Overlay{
      largestBatchId: ${this.largestBatchId},
      mutation: ${this.mutation.toString()}
    }`}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class aC{constructor(e,t,n,r,i=n7.min(),s=n7.min(),a=rV.EMPTY_BYTE_STRING){this.target=e,this.targetId=t,this.purpose=n,this.sequenceNumber=r,this.snapshotVersion=i,this.lastLimboFreeSnapshotVersion=s,this.resumeToken=a}withSequenceNumber(e){return new aC(this.target,this.targetId,this.purpose,e,this.snapshotVersion,this.lastLimboFreeSnapshotVersion,this.resumeToken)}withResumeToken(e,t){return new aC(this.target,this.targetId,this.purpose,this.sequenceNumber,t,this.lastLimboFreeSnapshotVersion,e)}withLastLimboFreeSnapshotVersion(e){return new aC(this.target,this.targetId,this.purpose,this.sequenceNumber,this.snapshotVersion,e,this.resumeToken)}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class ax{constructor(e){this.ie=e}}function aR(e,t){let n=t.key,r={prefixPath:n.getCollectionPath().popLast().toArray(),collectionGroup:n.collectionGroup,documentId:n.path.lastSegment(),readTime:aD(t.readTime),hasCommittedMutations:t.hasCommittedMutations};if(t.isFoundDocument()){var i;r.document={name:sQ(i=e.ie,t.key),fields:t.data.value.mapValue.fields,updateTime:sz(i,t.version.toTimestamp()),createTime:sz(i,t.createTime.toTimestamp())}}else if(t.isNoDocument())r.noDocument={path:n.path.toArray(),readTime:aN(t.version)};else{if(!t.isUnknownDocument())return nK();r.unknownDocument={path:n.path.toArray(),version:aN(t.version)}}return r}function aD(e){let t=e.toTimestamp();return[t.seconds,t.nanoseconds]}function aN(e){let t=e.toTimestamp();return{seconds:t.seconds,nanoseconds:t.nanoseconds}}function aO(e){let t=new n8(e.seconds,e.nanoseconds);return n7.fromTimestamp(t)}function aP(e,t){let n=(t.baseMutations||[]).map(t=>s3(e.ie,t));for(let r=0;r<t.mutations.length-1;++r){let i=t.mutations[r];if(r+1<t.mutations.length&&void 0!==t.mutations[r+1].transform){let s=t.mutations[r+1];i.updateTransforms=s.transform.fieldTransforms,t.mutations.splice(r+1,1),++r}}let a=t.mutations.map(t=>s3(e.ie,t)),o=n8.fromMillis(t.localWriteTimeMs);return new aS(t.batchId,o,n,a)}function aL(e){var t;let n;let r=aO(e.readTime),i=void 0!==e.lastLimboFreeSnapshotVersion?aO(e.lastLimboFreeSnapshotVersion):n7.min();return void 0!==e.query.documents?(1===(t=e.query).documents.length||nK(),n=iG(iV(sJ(t.documents[0])))):n=iG(s9(e.query)),new aC(n,e.targetId,0,e.lastListenSequenceNumber,r,i,rV.fromBase64String(e.resumeToken))}function aM(e,t){let n;let r=aN(t.snapshotVersion),i=aN(t.lastLimboFreeSnapshotVersion);n=iP(t.target)?s6(e.ie,t.target):s5(e.ie,t.target);let s=t.resumeToken.toBase64();return{targetId:t.targetId,canonicalId:iN(t.target),readTime:r,resumeToken:s,lastListenSequenceNumber:t.sequenceNumber,lastLimboFreeSnapshotVersion:i,query:n}}function aF(e){let t=s9({parent:e.parent,structuredQuery:e.structuredQuery});return"LAST"===e.limitType?iH(t,t.limit,"L"):t}function aU(e,t){return new aA(t.largestBatchId,s3(e.ie,t.overlayMutation))}function aV(e,t){let n=t.path.lastSegment();return[e,at(t.path.popLast()),n]}function aq(e,t,n,r){return{indexId:e,uid:t.uid||"",sequenceNumber:n,readTime:aN(r.readTime),documentKey:at(r.documentKey.path),largestBatchId:r.largestBatchId}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class aB{getBundleMetadata(e,t){return aj(e).get(t).next(e=>{if(e)return{id:e.bundleId,createTime:aO(e.createTime),version:e.version}})}saveBundleMetadata(e,t){return aj(e).put({bundleId:t.id,createTime:aN(sK(t.createTime)),version:t.version})}getNamedQuery(e,t){return a$(e).get(t).next(e=>{if(e)return{name:e.name,query:aF(e.bundledQuery),readTime:aO(e.readTime)}})}saveNamedQuery(e,t){return a$(e).put({name:t.name,readTime:aN(sK(t.readTime)),bundledQuery:t.bundledQuery})}}function aj(e){return aE(e,"bundles")}function a$(e){return aE(e,"namedQueries")}/**
 * @license
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class az{constructor(e,t){this.yt=e,this.userId=t}static re(e,t){let n=t.uid||"";return new az(e,n)}getOverlay(e,t){return aG(e).get(aV(this.userId,t)).next(e=>e?aU(this.yt,e):null)}getOverlays(e,t){let n=sk();return ry.forEach(t,t=>this.getOverlay(e,t).next(e=>{null!==e&&n.set(t,e)})).next(()=>n)}saveOverlays(e,t,n){let r=[];return n.forEach((n,i)=>{let s=new aA(t,i);r.push(this.oe(e,s))}),ry.waitFor(r)}removeOverlaysForBatchId(e,t,n){let r=new Set;t.forEach(e=>r.add(at(e.getCollectionPath())));let i=[];return r.forEach(t=>{let r=IDBKeyRange.bound([this.userId,t,n],[this.userId,t,n+1],!1,!0);i.push(aG(e).Y("collectionPathOverlayIndex",r))}),ry.waitFor(i)}getOverlaysForCollection(e,t,n){let r=sk(),i=at(t),s=IDBKeyRange.bound([this.userId,i,n],[this.userId,i,Number.POSITIVE_INFINITY],!0);return aG(e).W("collectionPathOverlayIndex",s).next(e=>{for(let t of e){let n=aU(this.yt,t);r.set(n.getKey(),n)}return r})}getOverlaysForCollectionGroup(e,t,n,r){let i;let s=sk(),a=IDBKeyRange.bound([this.userId,t,n],[this.userId,t,Number.POSITIVE_INFINITY],!0);return aG(e).Z({index:"collectionGroupOverlayIndex",range:a},(e,t,n)=>{let a=aU(this.yt,t);s.size()<r||a.largestBatchId===i?(s.set(a.getKey(),a),i=a.largestBatchId):n.done()}).next(()=>s)}oe(e,t){return aG(e).put(function(e,t,n){let[r,i,s]=aV(t,n.mutation.key);return{userId:t,collectionPath:i,documentId:s,collectionGroup:n.mutation.key.getCollectionGroup(),largestBatchId:n.largestBatchId,overlayMutation:s4(e.ie,n.mutation)}}(this.yt,this.userId,t))}}function aG(e){return aE(e,"documentOverlays")}/**
 * @license
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class aK{constructor(){}ue(e,t){this.ce(e,t),t.ae()}ce(e,t){if("nullValue"in e)this.he(t,5);else if("booleanValue"in e)this.he(t,10),t.le(e.booleanValue?1:0);else if("integerValue"in e)this.he(t,15),t.le(rj(e.integerValue));else if("doubleValue"in e){let n=rj(e.doubleValue);isNaN(n)?this.he(t,13):(this.he(t,15),rM(n)?t.le(0):t.le(n))}else if("timestampValue"in e){let r=e.timestampValue;this.he(t,20),"string"==typeof r?t.fe(r):(t.fe(`${r.seconds||""}`),t.le(r.nanos||0))}else if("stringValue"in e)this.de(e.stringValue,t),this._e(t);else if("bytesValue"in e)this.he(t,30),t.we(r$(e.bytesValue)),this._e(t);else if("referenceValue"in e)this.me(e.referenceValue,t);else if("geoPointValue"in e){let i=e.geoPointValue;this.he(t,45),t.le(i.latitude||0),t.le(i.longitude||0)}else"mapValue"in e?r9(e)?this.he(t,Number.MAX_SAFE_INTEGER):(this.ge(e.mapValue,t),this._e(t)):"arrayValue"in e?(this.ye(e.arrayValue,t),this._e(t)):nK()}de(e,t){this.he(t,25),this.pe(e,t)}pe(e,t){t.fe(e)}ge(e,t){let n=e.fields||{};for(let r of(this.he(t,55),Object.keys(n)))this.de(r,t),this.ce(n[r],t)}ye(e,t){let n=e.values||[];for(let r of(this.he(t,50),n))this.ce(r,t)}me(e,t){this.he(t,37),ri.fromName(e).path.forEach(e=>{this.he(t,60),this.pe(e,t)})}he(e,t){e.le(t)}_e(e){e.le(2)}}function aH(e){let t=64-function(e){let t=0;for(let n=0;n<8;++n){let r=function(e){if(0===e)return 8;let t=0;return e>>4==0&&(t+=4,e<<=4),e>>6==0&&(t+=2,e<<=2),e>>7==0&&(t+=1),t}(255&e[n]);if(t+=r,8!==r)break}return t}(e);return Math.ceil(t/8)}aK.Ie=new aK;class aW{constructor(){this.buffer=new Uint8Array(1024),this.position=0}Te(e){let t=e[Symbol.iterator](),n=t.next();for(;!n.done;)this.Ee(n.value),n=t.next();this.Ae()}Re(e){let t=e[Symbol.iterator](),n=t.next();for(;!n.done;)this.be(n.value),n=t.next();this.Pe()}ve(e){for(let t of e){let n=t.charCodeAt(0);if(n<128)this.Ee(n);else if(n<2048)this.Ee(960|n>>>6),this.Ee(128|63&n);else if(t<"\ud800"||"\udbff"<t)this.Ee(480|n>>>12),this.Ee(128|63&n>>>6),this.Ee(128|63&n);else{let r=t.codePointAt(0);this.Ee(240|r>>>18),this.Ee(128|63&r>>>12),this.Ee(128|63&r>>>6),this.Ee(128|63&r)}}this.Ae()}Ve(e){for(let t of e){let n=t.charCodeAt(0);if(n<128)this.be(n);else if(n<2048)this.be(960|n>>>6),this.be(128|63&n);else if(t<"\ud800"||"\udbff"<t)this.be(480|n>>>12),this.be(128|63&n>>>6),this.be(128|63&n);else{let r=t.codePointAt(0);this.be(240|r>>>18),this.be(128|63&r>>>12),this.be(128|63&r>>>6),this.be(128|63&r)}}this.Pe()}Se(e){let t=this.De(e),n=aH(t);this.Ce(1+n),this.buffer[this.position++]=255&n;for(let r=t.length-n;r<t.length;++r)this.buffer[this.position++]=255&t[r]}xe(e){let t=this.De(e),n=aH(t);this.Ce(1+n),this.buffer[this.position++]=~(255&n);for(let r=t.length-n;r<t.length;++r)this.buffer[this.position++]=~(255&t[r])}Ne(){this.ke(255),this.ke(255)}Oe(){this.Me(255),this.Me(255)}reset(){this.position=0}seed(e){this.Ce(e.length),this.buffer.set(e,this.position),this.position+=e.length}Fe(){return this.buffer.slice(0,this.position)}De(e){let t=function(e){let t=new DataView(new ArrayBuffer(8));return t.setFloat64(0,e,!1),new Uint8Array(t.buffer)}(e),n=0!=(128&t[0]);t[0]^=n?255:128;for(let r=1;r<t.length;++r)t[r]^=n?255:0;return t}Ee(e){let t=255&e;0===t?(this.ke(0),this.ke(255)):255===t?(this.ke(255),this.ke(0)):this.ke(t)}be(e){let t=255&e;0===t?(this.Me(0),this.Me(255)):255===t?(this.Me(255),this.Me(0)):this.Me(e)}Ae(){this.ke(0),this.ke(1)}Pe(){this.Me(0),this.Me(1)}ke(e){this.Ce(1),this.buffer[this.position++]=e}Me(e){this.Ce(1),this.buffer[this.position++]=~e}Ce(e){let t=e+this.position;if(t<=this.buffer.length)return;let n=2*this.buffer.length;n<t&&(n=t);let r=new Uint8Array(n);r.set(this.buffer),this.buffer=r}}class aQ{constructor(e){this.$e=e}we(e){this.$e.Te(e)}fe(e){this.$e.ve(e)}le(e){this.$e.Se(e)}ae(){this.$e.Ne()}}class aY{constructor(e){this.$e=e}we(e){this.$e.Re(e)}fe(e){this.$e.Ve(e)}le(e){this.$e.xe(e)}ae(){this.$e.Oe()}}class aX{constructor(){this.$e=new aW,this.Be=new aQ(this.$e),this.Le=new aY(this.$e)}seed(e){this.$e.seed(e)}qe(e){return 0===e?this.Be:this.Le}Fe(){return this.$e.Fe()}reset(){this.$e.reset()}}/**
 * @license
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class aJ{constructor(e,t,n,r){this.indexId=e,this.documentKey=t,this.arrayValue=n,this.directionalValue=r}Ue(){let e=this.directionalValue.length,t=0===e||255===this.directionalValue[e-1]?e+1:e,n=new Uint8Array(t);return n.set(this.directionalValue,0),t!==e?n.set([0],this.directionalValue.length):++n[n.length-1],new aJ(this.indexId,this.documentKey,this.arrayValue,n)}}function aZ(e,t){let n=e.indexId-t.indexId;return 0!==n?n:0!==(n=a0(e.arrayValue,t.arrayValue))?n:0!==(n=a0(e.directionalValue,t.directionalValue))?n:ri.comparator(e.documentKey,t.documentKey)}function a0(e,t){for(let n=0;n<e.length&&n<t.length;++n){let r=e[n]-t[n];if(0!==r)return r}return e.length-t.length}/**
 * @license
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class a1{constructor(e){for(let t of(this.collectionId=null!=e.collectionGroup?e.collectionGroup:e.path.lastSegment(),this.Ke=e.orderBy,this.Ge=[],e.filters)){let n=t;n.isInequality()?this.Qe=n:this.Ge.push(n)}}je(e){e.collectionGroup===this.collectionId||nK();let t=ra(e);if(void 0!==t&&!this.We(t))return!1;let n=ro(e),r=0,i=0;for(;r<n.length&&this.We(n[r]);++r);if(r===n.length)return!0;if(void 0!==this.Qe){let s=n[r];if(!this.ze(this.Qe,s)||!this.He(this.Ke[i++],s))return!1;++r}for(;r<n.length;++r){let a=n[r];if(i>=this.Ke.length||!this.He(this.Ke[i++],a))return!1}return!0}We(e){for(let t of this.Ge)if(this.ze(t,e))return!0;return!1}ze(e,t){if(void 0===e||!e.field.isEqual(t.fieldPath))return!1;let n="array-contains"===e.op||"array-contains-any"===e.op;return 2===t.kind===n}He(e,t){return!!e.field.isEqual(t.fieldPath)&&(0===t.kind&&"asc"===e.dir||1===t.kind&&"desc"===e.dir)}}function a2(e){return e instanceof is}function a4(e){var t;return e instanceof ia&&iu(t=e)&&io(t)}function a3(e){return a2(e)||a4(e)||function(e){if(e instanceof ia&&il(e)){for(let t of e.getFilters())if(!a2(t)&&!a4(t))return!1;return!0}return!1}(e)}function a6(e,t){return e instanceof is||e instanceof ia||nK(),t instanceof is||t instanceof ia||nK(),a9(e instanceof is?t instanceof is?ia.create([e,t],"and"):a5(e,t):t instanceof is?a5(t,e):function(e,t){if(e.filters.length>0&&t.filters.length>0||nK(),io(e)&&io(t))return ic(e,t.getFilters());let n=il(e)?e:t,r=il(e)?t:e,i=n.filters.map(e=>a6(e,r));return ia.create(i,"or")}(e,t))}function a5(e,t){if(io(t))return ic(t,e.getFilters());{let n=t.filters.map(t=>a6(e,t));return ia.create(n,"or")}}function a9(e){if(e instanceof is||e instanceof ia||nK(),e instanceof is)return e;let t=e.getFilters();if(1===t.length)return a9(t[0]);if(iu(e))return e;let n=t.map(e=>a9(e)),r=[];return n.forEach(t=>{t instanceof is?r.push(t):t instanceof ia&&(t.op===e.op?r.push(...t.filters):r.push(t))}),1===r.length?r[0]:ia.create(r,e.op)}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class a8{constructor(){this.Je=new a7}addToCollectionParentIndex(e,t){return this.Je.add(t),ry.resolve()}getCollectionParents(e,t){return ry.resolve(this.Je.getEntries(t))}addFieldIndex(e,t){return ry.resolve()}deleteFieldIndex(e,t){return ry.resolve()}getDocumentsMatchingTarget(e,t){return ry.resolve(null)}getIndexType(e,t){return ry.resolve(0)}getFieldIndexes(e,t){return ry.resolve([])}getNextCollectionGroupToUpdate(e){return ry.resolve(null)}getMinOffset(e,t){return ry.resolve(rd.min())}getMinOffsetFromCollectionGroup(e,t){return ry.resolve(rd.min())}updateCollectionGroup(e,t,n){return ry.resolve()}updateIndexEntries(e,t){return ry.resolve()}}class a7{constructor(){this.index={}}add(e){let t=e.lastSegment(),n=e.popLast(),r=this.index[t]||new iE(rt.comparator),i=!r.has(n);return this.index[t]=r.add(n),i}has(e){let t=e.lastSegment(),n=e.popLast(),r=this.index[t];return r&&r.has(n)}getEntries(e){return(this.index[e]||new iE(rt.comparator)).toArray()}}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let oe=new Uint8Array(0);class ot{constructor(e,t){this.user=e,this.databaseId=t,this.Ye=new a7,this.Xe=new sb(e=>iN(e),(e,t)=>iO(e,t)),this.uid=e.uid||""}addToCollectionParentIndex(e,t){if(!this.Ye.has(t)){let n=t.lastSegment(),r=t.popLast();e.addOnCommittedListener(()=>{this.Ye.add(t)});let i={collectionId:n,parent:at(r)};return on(e).put(i)}return ry.resolve()}getCollectionParents(e,t){let n=[],r=IDBKeyRange.bound([t,""],[t+"\0",""],!1,!0);return on(e).W(r).next(e=>{for(let r of e){if(r.collectionId!==t)break;n.push(an(r.parent))}return n})}addFieldIndex(e,t){let n=oi(e),r={indexId:t.indexId,collectionGroup:t.collectionGroup,fields:t.fields.map(e=>[e.fieldPath.canonicalString(),e.kind])};delete r.indexId;let i=n.add(r);if(t.indexState){let s=os(e);return i.next(e=>{s.put(aq(e,this.user,t.indexState.sequenceNumber,t.indexState.offset))})}return i.next()}deleteFieldIndex(e,t){let n=oi(e),r=os(e),i=or(e);return n.delete(t.indexId).next(()=>r.delete(IDBKeyRange.bound([t.indexId],[t.indexId+1],!1,!0))).next(()=>i.delete(IDBKeyRange.bound([t.indexId],[t.indexId+1],!1,!0)))}getDocumentsMatchingTarget(e,t){let n=or(e),r=!0,i=new Map;return ry.forEach(this.Ze(t),t=>this.tn(e,t).next(e=>{r&&(r=!!e),i.set(t,e)})).next(()=>{if(r){let e=sx(),s=[];return ry.forEach(i,(r,i)=>{nj("IndexedDbIndexManager",`Using index id=${r.indexId}|cg=${r.collectionGroup}|f=${r.fields.map(e=>`${e.fieldPath}:${e.kind}`).join(",")} to execute ${iN(t)}`);let a=function(e,t){let n=ra(t);if(void 0===n)return null;for(let r of iL(e,n.fieldPath))switch(r.op){case"array-contains-any":return r.value.arrayValue.values||[];case"array-contains":return[r.value]}return null}(i,r),o=function(e,t){let n=new Map;for(let r of ro(t))for(let i of iL(e,r.fieldPath))switch(i.op){case"==":case"in":n.set(r.fieldPath.canonicalString(),i.value);break;case"not-in":case"!=":return n.set(r.fieldPath.canonicalString(),i.value),Array.from(n.values())}return null}(i,r),l=function(e,t){let n=[],r=!0;for(let i of ro(t)){let s=0===i.kind?iM(e,i.fieldPath,e.startAt):iF(e,i.fieldPath,e.startAt);n.push(s.value),r&&(r=s.inclusive)}return new ie(n,r)}(i,r),u=function(e,t){let n=[],r=!0;for(let i of ro(t)){let s=0===i.kind?iF(e,i.fieldPath,e.endAt):iM(e,i.fieldPath,e.endAt);n.push(s.value),r&&(r=s.inclusive)}return new ie(n,r)}(i,r),c=this.en(r,i,l),h=this.en(r,i,u),d=this.nn(r,i,o),f=this.sn(r.indexId,a,c,l.inclusive,h,u.inclusive,d);return ry.forEach(f,r=>n.J(r,t.limit).next(t=>{t.forEach(t=>{let n=ri.fromSegments(t.documentKey);e.has(n)||(e=e.add(n),s.push(n))})}))}).next(()=>s)}return ry.resolve(null)})}Ze(e){let t=this.Xe.get(e);return t||(t=0===e.filters.length?[e]:(function(e){if(0===e.getFilters().length)return[];let t=function e(t){if(t instanceof is||t instanceof ia||nK(),t instanceof is)return t;if(1===t.filters.length)return e(t.filters[0]);let n=t.filters.map(t=>e(t)),r=ia.create(n,t.op);return a3(r=a9(r))?r:(r instanceof ia||nK(),io(r)||nK(),r.filters.length>1||nK(),r.filters.reduce((e,t)=>a6(e,t)))}(/**
 * @license
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function e(t){var n,r;if(t instanceof is||t instanceof ia||nK(),t instanceof is){if(t instanceof iy){let i=(null===(r=null===(n=t.value.arrayValue)||void 0===n?void 0:n.values)||void 0===r?void 0:r.map(e=>is.create(t.field,"==",e)))||[];return ia.create(i,"or")}return t}let s=t.filters.map(t=>e(t));return ia.create(s,t.op)}(e));return a3(t)||nK(),a2(t)||a4(t)?[t]:t.getFilters()})(ia.create(e.filters,"and")).map(t=>iD(e.path,e.collectionGroup,e.orderBy,t.getFilters(),e.limit,e.startAt,e.endAt)),this.Xe.set(e,t)),t}sn(e,t,n,r,i,s,a){let o=(null!=t?t.length:1)*Math.max(n.length,i.length),l=o/(null!=t?t.length:1),u=[];for(let c=0;c<o;++c){let h=t?this.rn(t[c/l]):oe,d=this.on(e,h,n[c%l],r),f=this.un(e,h,i[c%l],s),p=a.map(t=>this.on(e,h,t,!0));u.push(...this.createRange(d,f,p))}return u}on(e,t,n,r){let i=new aJ(e,ri.empty(),t,n);return r?i:i.Ue()}un(e,t,n,r){let i=new aJ(e,ri.empty(),t,n);return r?i.Ue():i}tn(e,t){let n=new a1(t),r=null!=t.collectionGroup?t.collectionGroup:t.path.lastSegment();return this.getFieldIndexes(e,r).next(e=>{let t=null;for(let r of e)n.je(r)&&(!t||r.fields.length>t.fields.length)&&(t=r);return t})}getIndexType(e,t){let n=2,r=this.Ze(t);return ry.forEach(r,t=>this.tn(e,t).next(e=>{e?0!==n&&e.fields.length<function(e){let t=new iE(rr.comparator),n=!1;for(let r of e.filters)for(let i of r.getFlattenedFilters())i.field.isKeyField()||("array-contains"===i.op||"array-contains-any"===i.op?n=!0:t=t.add(i.field));for(let s of e.orderBy)s.field.isKeyField()||(t=t.add(s.field));return t.size+(n?1:0)}(t)&&(n=1):n=0})).next(()=>null!==t.limit&&r.length>1&&2===n?1:n)}cn(e,t){let n=new aX;for(let r of ro(e)){let i=t.data.field(r.fieldPath);if(null==i)return null;let s=n.qe(r.kind);aK.Ie.ue(i,s)}return n.Fe()}rn(e){let t=new aX;return aK.Ie.ue(e,t.qe(0)),t.Fe()}an(e,t){let n=new aX;return aK.Ie.ue(r0(this.databaseId,t),n.qe(function(e){let t=ro(e);return 0===t.length?0:t[t.length-1].kind}(e))),n.Fe()}nn(e,t,n){if(null===n)return[];let r=[];r.push(new aX);let i=0;for(let s of ro(e)){let a=n[i++];for(let o of r)if(this.hn(t,s.fieldPath)&&r2(a))r=this.ln(r,s,a);else{let l=o.qe(s.kind);aK.Ie.ue(a,l)}}return this.fn(r)}en(e,t,n){return this.nn(e,t,n.position)}fn(e){let t=[];for(let n=0;n<e.length;++n)t[n]=e[n].Fe();return t}ln(e,t,n){let r=[...e],i=[];for(let s of n.arrayValue.values||[])for(let a of r){let o=new aX;o.seed(a.Fe()),aK.Ie.ue(s,o.qe(t.kind)),i.push(o)}return i}hn(e,t){return!!e.filters.find(e=>e instanceof is&&e.field.isEqual(t)&&("in"===e.op||"not-in"===e.op))}getFieldIndexes(e,t){let n=oi(e),r=os(e);return(t?n.W("collectionGroupIndex",IDBKeyRange.bound(t,t)):n.W()).next(e=>{let t=[];return ry.forEach(e,e=>r.get([e.indexId,this.uid]).next(n=>{t.push(function(e,t){let n=t?new ru(t.sequenceNumber,new rd(aO(t.readTime),new ri(an(t.documentKey)),t.largestBatchId)):ru.empty(),r=e.fields.map(([e,t])=>new rl(rr.fromServerFormat(e),t));return new rs(e.indexId,e.collectionGroup,r,n)}(e,n))})).next(()=>t)})}getNextCollectionGroupToUpdate(e){return this.getFieldIndexes(e).next(e=>0===e.length?null:(e.sort((e,t)=>{let n=e.indexState.sequenceNumber-t.indexState.sequenceNumber;return 0!==n?n:n5(e.collectionGroup,t.collectionGroup)}),e[0].collectionGroup))}updateCollectionGroup(e,t,n){let r=oi(e),i=os(e);return this.dn(e).next(e=>r.W("collectionGroupIndex",IDBKeyRange.bound(t,t)).next(t=>ry.forEach(t,t=>i.put(aq(t.indexId,this.user,e,n)))))}updateIndexEntries(e,t){let n=new Map;return ry.forEach(t,(t,r)=>{let i=n.get(t.collectionGroup);return(i?ry.resolve(i):this.getFieldIndexes(e,t.collectionGroup)).next(i=>(n.set(t.collectionGroup,i),ry.forEach(i,n=>this._n(e,t,n).next(t=>{let i=this.wn(r,n);return t.isEqual(i)?ry.resolve():this.mn(e,r,n,t,i)}))))})}gn(e,t,n,r){return or(e).put({indexId:r.indexId,uid:this.uid,arrayValue:r.arrayValue,directionalValue:r.directionalValue,orderedDocumentKey:this.an(n,t.key),documentKey:t.key.path.toArray()})}yn(e,t,n,r){return or(e).delete([r.indexId,this.uid,r.arrayValue,r.directionalValue,this.an(n,t.key),t.key.path.toArray()])}_n(e,t,n){let r=or(e),i=new iE(aZ);return r.Z({index:"documentKeyIndex",range:IDBKeyRange.only([n.indexId,this.uid,this.an(n,t)])},(e,r)=>{i=i.add(new aJ(n.indexId,t,r.arrayValue,r.directionalValue))}).next(()=>i)}wn(e,t){let n=new iE(aZ),r=this.cn(t,e);if(null==r)return n;let i=ra(t);if(null!=i){let s=e.data.field(i.fieldPath);if(r2(s))for(let a of s.arrayValue.values||[])n=n.add(new aJ(t.indexId,e.key,this.rn(a),r))}else n=n.add(new aJ(t.indexId,e.key,oe,r));return n}mn(e,t,n,r,i){nj("IndexedDbIndexManager","Updating index entries for document '%s'",t.key);let s=[];return function(e,t,n,r,i){let s=e.getIterator(),a=t.getIterator(),o=ik(s),l=ik(a);for(;o||l;){let u=!1,c=!1;if(o&&l){let h=n(o,l);h<0?c=!0:h>0&&(u=!0)}else null!=o?c=!0:u=!0;u?(r(l),l=ik(a)):c?(i(o),o=ik(s)):(o=ik(s),l=ik(a))}}(r,i,aZ,r=>{s.push(this.gn(e,t,n,r))},r=>{s.push(this.yn(e,t,n,r))}),ry.waitFor(s)}dn(e){let t=1;return os(e).Z({index:"sequenceNumberIndex",reverse:!0,range:IDBKeyRange.upperBound([this.uid,Number.MAX_SAFE_INTEGER])},(e,n,r)=>{r.done(),t=n.sequenceNumber+1}).next(()=>t)}createRange(e,t,n){n=n.sort((e,t)=>aZ(e,t)).filter((e,t,n)=>!t||0!==aZ(e,n[t-1]));let r=[];for(let i of(r.push(e),n)){let s=aZ(i,e),a=aZ(i,t);if(0===s)r[0]=e.Ue();else if(s>0&&a<0)r.push(i),r.push(i.Ue());else if(a>0)break}r.push(t);let o=[];for(let l=0;l<r.length;l+=2){if(this.pn(r[l],r[l+1]))return[];let u=[r[l].indexId,this.uid,r[l].arrayValue,r[l].directionalValue,oe,[]],c=[r[l+1].indexId,this.uid,r[l+1].arrayValue,r[l+1].directionalValue,oe,[]];o.push(IDBKeyRange.bound(u,c))}return o}pn(e,t){return aZ(e,t)>0}getMinOffsetFromCollectionGroup(e,t){return this.getFieldIndexes(e,t).next(oa)}getMinOffset(e,t){return ry.mapArray(this.Ze(t),t=>this.tn(e,t).next(e=>e||nK())).next(oa)}}function on(e){return aE(e,"collectionParents")}function or(e){return aE(e,"indexEntries")}function oi(e){return aE(e,"indexConfiguration")}function os(e){return aE(e,"indexState")}function oa(e){0!==e.length||nK();let t=e[0].indexState.offset,n=t.largestBatchId;for(let r=1;r<e.length;r++){let i=e[r].indexState.offset;0>rf(i,t)&&(t=i),n<i.largestBatchId&&(n=i.largestBatchId)}return new rd(t.readTime,t.documentKey,n)}/**
 * @license
 * Copyright 2018 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let oo={didRun:!1,sequenceNumbersCollected:0,targetsRemoved:0,documentsRemoved:0};class ol{constructor(e,t,n){this.cacheSizeCollectionThreshold=e,this.percentileToCollect=t,this.maximumSequenceNumbersToCollect=n}static withCacheSize(e){return new ol(e,ol.DEFAULT_COLLECTION_PERCENTILE,ol.DEFAULT_MAX_SEQUENCE_NUMBERS_TO_COLLECT)}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function ou(e,t,n){let r=e.store("mutations"),i=e.store("documentMutations"),s=[],a=IDBKeyRange.only(n.batchId),o=0,l=r.Z({range:a},(e,t,n)=>(o++,n.delete()));s.push(l.next(()=>{1===o||nK()}));let u=[];for(let c of n.mutations){var h,d;let f=(h=c.key.path,d=n.batchId,[t,at(h),d]);s.push(i.delete(f)),u.push(c.key)}return ry.waitFor(s).next(()=>u)}function oc(e){let t;if(!e)return 0;if(e.document)t=e.document;else if(e.unknownDocument)t=e.unknownDocument;else{if(!e.noDocument)throw nK();t=e.noDocument}return JSON.stringify(t).length}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ol.DEFAULT_COLLECTION_PERCENTILE=10,ol.DEFAULT_MAX_SEQUENCE_NUMBERS_TO_COLLECT=1e3,ol.DEFAULT=new ol(41943040,ol.DEFAULT_COLLECTION_PERCENTILE,ol.DEFAULT_MAX_SEQUENCE_NUMBERS_TO_COLLECT),ol.DISABLED=new ol(-1,0,0);class oh{constructor(e,t,n,r){this.userId=e,this.yt=t,this.indexManager=n,this.referenceDelegate=r,this.In={}}static re(e,t,n,r){""!==e.uid||nK();let i=e.isAuthenticated()?e.uid:"";return new oh(i,t,n,r)}checkEmpty(e){let t=!0,n=IDBKeyRange.bound([this.userId,Number.NEGATIVE_INFINITY],[this.userId,Number.POSITIVE_INFINITY]);return of(e).Z({index:"userMutationsIndex",range:n},(e,n,r)=>{t=!1,r.done()}).next(()=>t)}addMutationBatch(e,t,n,r){let i=op(e),s=of(e);return s.add({}).next(a=>{"number"==typeof a||nK();let o=new aS(a,t,n,r),l=function(e,t,n){let r=n.baseMutations.map(t=>s4(e.ie,t)),i=n.mutations.map(t=>s4(e.ie,t));return{userId:t,batchId:n.batchId,localWriteTimeMs:n.localWriteTime.toMillis(),baseMutations:r,mutations:i}}(this.yt,this.userId,o),u=[],c=new iE((e,t)=>n5(e.canonicalString(),t.canonicalString()));for(let h of r){let d=[this.userId,at(h.key.path),a];c=c.add(h.key.path.popLast()),u.push(s.put(l)),u.push(i.put(d,ai))}return c.forEach(t=>{u.push(this.indexManager.addToCollectionParentIndex(e,t))}),e.addOnCommittedListener(()=>{this.In[a]=o.keys()}),ry.waitFor(u).next(()=>o)})}lookupMutationBatch(e,t){return of(e).get(t).next(e=>e?(e.userId===this.userId||nK(),aP(this.yt,e)):null)}Tn(e,t){return this.In[t]?ry.resolve(this.In[t]):this.lookupMutationBatch(e,t).next(e=>{if(e){let n=e.keys();return this.In[t]=n,n}return null})}getNextMutationBatchAfterBatchId(e,t){let n=t+1,r=IDBKeyRange.lowerBound([this.userId,n]),i=null;return of(e).Z({index:"userMutationsIndex",range:r},(e,t,r)=>{t.userId===this.userId&&(t.batchId>=n||nK(),i=aP(this.yt,t)),r.done()}).next(()=>i)}getHighestUnacknowledgedBatchId(e){let t=IDBKeyRange.upperBound([this.userId,Number.POSITIVE_INFINITY]),n=-1;return of(e).Z({index:"userMutationsIndex",range:t,reverse:!0},(e,t,r)=>{n=t.batchId,r.done()}).next(()=>n)}getAllMutationBatches(e){let t=IDBKeyRange.bound([this.userId,-1],[this.userId,Number.POSITIVE_INFINITY]);return of(e).W("userMutationsIndex",t).next(e=>e.map(e=>aP(this.yt,e)))}getAllMutationBatchesAffectingDocumentKey(e,t){let n=[this.userId,at(t.path)],r=IDBKeyRange.lowerBound(n),i=[];return op(e).Z({range:r},(n,r,s)=>{let[a,o,l]=n,u=an(o);if(a===this.userId&&t.path.isEqual(u))return of(e).get(l).next(e=>{if(!e)throw nK();e.userId===this.userId||nK(),i.push(aP(this.yt,e))});s.done()}).next(()=>i)}getAllMutationBatchesAffectingDocumentKeys(e,t){let n=new iE(n5),r=[];return t.forEach(t=>{let i=[this.userId,at(t.path)],s=IDBKeyRange.lowerBound(i),a=op(e).Z({range:s},(e,r,i)=>{let[s,a,o]=e,l=an(a);s===this.userId&&t.path.isEqual(l)?n=n.add(o):i.done()});r.push(a)}),ry.waitFor(r).next(()=>this.En(e,n))}getAllMutationBatchesAffectingQuery(e,t){let n=t.path,r=n.length+1,i=[this.userId,at(n)],s=IDBKeyRange.lowerBound(i),a=new iE(n5);return op(e).Z({range:s},(e,t,i)=>{let[s,o,l]=e,u=an(o);s===this.userId&&n.isPrefixOf(u)?u.length===r&&(a=a.add(l)):i.done()}).next(()=>this.En(e,a))}En(e,t){let n=[],r=[];return t.forEach(t=>{r.push(of(e).get(t).next(e=>{if(null===e)throw nK();e.userId===this.userId||nK(),n.push(aP(this.yt,e))}))}),ry.waitFor(r).next(()=>n)}removeMutationBatch(e,t){return ou(e.se,this.userId,t).next(n=>(e.addOnCommittedListener(()=>{this.An(t.batchId)}),ry.forEach(n,t=>this.referenceDelegate.markPotentiallyOrphaned(e,t))))}An(e){delete this.In[e]}performConsistencyCheck(e){return this.checkEmpty(e).next(t=>{if(!t)return ry.resolve();let n=IDBKeyRange.lowerBound([this.userId]),r=[];return op(e).Z({range:n},(e,t,n)=>{if(e[0]===this.userId){let i=an(e[1]);r.push(i)}else n.done()}).next(()=>{0===r.length||nK()})})}containsKey(e,t){return od(e,this.userId,t)}Rn(e){return om(e).get(this.userId).next(e=>e||{userId:this.userId,lastAcknowledgedBatchId:-1,lastStreamToken:""})}}function od(e,t,n){let r=[t,at(n.path)],i=r[1],s=IDBKeyRange.lowerBound(r),a=!1;return op(e).Z({range:s,X:!0},(e,n,r)=>{let[s,o,l]=e;s===t&&o===i&&(a=!0),r.done()}).next(()=>a)}function of(e){return aE(e,"mutations")}function op(e){return aE(e,"documentMutations")}function om(e){return aE(e,"mutationQueues")}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class og{constructor(e){this.bn=e}next(){return this.bn+=2,this.bn}static Pn(){return new og(0)}static vn(){return new og(-1)}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class oy{constructor(e,t){this.referenceDelegate=e,this.yt=t}allocateTargetId(e){return this.Vn(e).next(t=>{let n=new og(t.highestTargetId);return t.highestTargetId=n.next(),this.Sn(e,t).next(()=>t.highestTargetId)})}getLastRemoteSnapshotVersion(e){return this.Vn(e).next(e=>n7.fromTimestamp(new n8(e.lastRemoteSnapshotVersion.seconds,e.lastRemoteSnapshotVersion.nanoseconds)))}getHighestSequenceNumber(e){return this.Vn(e).next(e=>e.highestListenSequenceNumber)}setTargetsMetadata(e,t,n){return this.Vn(e).next(r=>(r.highestListenSequenceNumber=t,n&&(r.lastRemoteSnapshotVersion=n.toTimestamp()),t>r.highestListenSequenceNumber&&(r.highestListenSequenceNumber=t),this.Sn(e,r)))}addTargetData(e,t){return this.Dn(e,t).next(()=>this.Vn(e).next(n=>(n.targetCount+=1,this.Cn(t,n),this.Sn(e,n))))}updateTargetData(e,t){return this.Dn(e,t)}removeTargetData(e,t){return this.removeMatchingKeysForTargetId(e,t.targetId).next(()=>ov(e).delete(t.targetId)).next(()=>this.Vn(e)).next(t=>(t.targetCount>0||nK(),t.targetCount-=1,this.Sn(e,t)))}removeTargets(e,t,n){let r=0,i=[];return ov(e).Z((s,a)=>{let o=aL(a);o.sequenceNumber<=t&&null===n.get(o.targetId)&&(r++,i.push(this.removeTargetData(e,o)))}).next(()=>ry.waitFor(i)).next(()=>r)}forEachTarget(e,t){return ov(e).Z((e,n)=>{let r=aL(n);t(r)})}Vn(e){return ow(e).get("targetGlobalKey").next(e=>(null!==e||nK(),e))}Sn(e,t){return ow(e).put("targetGlobalKey",t)}Dn(e,t){return ov(e).put(aM(this.yt,t))}Cn(e,t){let n=!1;return e.targetId>t.highestTargetId&&(t.highestTargetId=e.targetId,n=!0),e.sequenceNumber>t.highestListenSequenceNumber&&(t.highestListenSequenceNumber=e.sequenceNumber,n=!0),n}getTargetCount(e){return this.Vn(e).next(e=>e.targetCount)}getTargetData(e,t){let n=iN(t),r=IDBKeyRange.bound([n,Number.NEGATIVE_INFINITY],[n,Number.POSITIVE_INFINITY]),i=null;return ov(e).Z({range:r,index:"queryTargetsIndex"},(e,n,r)=>{let s=aL(n);iO(t,s.target)&&(i=s,r.done())}).next(()=>i)}addMatchingKeys(e,t,n){let r=[],i=o_(e);return t.forEach(t=>{let s=at(t.path);r.push(i.put({targetId:n,path:s})),r.push(this.referenceDelegate.addReference(e,n,t))}),ry.waitFor(r)}removeMatchingKeys(e,t,n){let r=o_(e);return ry.forEach(t,t=>{let i=at(t.path);return ry.waitFor([r.delete([n,i]),this.referenceDelegate.removeReference(e,n,t)])})}removeMatchingKeysForTargetId(e,t){let n=o_(e),r=IDBKeyRange.bound([t],[t+1],!1,!0);return n.delete(r)}getMatchingKeysForTargetId(e,t){let n=IDBKeyRange.bound([t],[t+1],!1,!0),r=o_(e),i=sx();return r.Z({range:n,X:!0},(e,t,n)=>{let r=an(e[1]),s=new ri(r);i=i.add(s)}).next(()=>i)}containsKey(e,t){let n=at(t.path),r=IDBKeyRange.bound([n],[n+"\0"],!1,!0),i=0;return o_(e).Z({index:"documentTargetsIndex",X:!0,range:r},([e,t],n,r)=>{0!==e&&(i++,r.done())}).next(()=>i>0)}ne(e,t){return ov(e).get(t).next(e=>e?aL(e):null)}}function ov(e){return aE(e,"targets")}function ow(e){return aE(e,"targetGlobal")}function o_(e){return aE(e,"targetDocuments")}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function ob([e,t],[n,r]){let i=n5(e,n);return 0===i?n5(t,r):i}class oI{constructor(e){this.xn=e,this.buffer=new iE(ob),this.Nn=0}kn(){return++this.Nn}On(e){let t=[e,this.kn()];if(this.buffer.size<this.xn)this.buffer=this.buffer.add(t);else{let n=this.buffer.last();0>ob(t,n)&&(this.buffer=this.buffer.delete(n).add(t))}}get maxValue(){return this.buffer.last()[0]}}class oT{constructor(e,t,n){this.garbageCollector=e,this.asyncQueue=t,this.localStore=n,this.Mn=null}start(){-1!==this.garbageCollector.params.cacheSizeCollectionThreshold&&this.Fn(6e4)}stop(){this.Mn&&(this.Mn.cancel(),this.Mn=null)}get started(){return null!==this.Mn}Fn(e){nj("LruGarbageCollector",`Garbage collection scheduled in ${e}ms`),this.Mn=this.asyncQueue.enqueueAfterDelay("lru_garbage_collection",e,async()=>{this.Mn=null;try{await this.localStore.collectGarbage(this.garbageCollector)}catch(e){rI(e)?nj("LruGarbageCollector","Ignoring IndexedDB error during garbage collection: ",e):await rg(e)}await this.Fn(3e5)})}}class oE{constructor(e,t){this.$n=e,this.params=t}calculateTargetCount(e,t){return this.$n.Bn(e).next(e=>Math.floor(t/100*e))}nthSequenceNumber(e,t){if(0===t)return ry.resolve(rx.at);let n=new oI(t);return this.$n.forEachTarget(e,e=>n.On(e.sequenceNumber)).next(()=>this.$n.Ln(e,e=>n.On(e))).next(()=>n.maxValue)}removeTargets(e,t,n){return this.$n.removeTargets(e,t,n)}removeOrphanedDocuments(e,t){return this.$n.removeOrphanedDocuments(e,t)}collect(e,t){return -1===this.params.cacheSizeCollectionThreshold?(nj("LruGarbageCollector","Garbage collection skipped; disabled"),ry.resolve(oo)):this.getCacheSize(e).next(n=>n<this.params.cacheSizeCollectionThreshold?(nj("LruGarbageCollector",`Garbage collection skipped; Cache size ${n} is lower than threshold ${this.params.cacheSizeCollectionThreshold}`),oo):this.qn(e,t))}getCacheSize(e){return this.$n.getCacheSize(e)}qn(e,t){let n,r,i,s,a,o,l;let u=Date.now();return this.calculateTargetCount(e,this.params.percentileToCollect).next(t=>(t>this.params.maximumSequenceNumbersToCollect?(nj("LruGarbageCollector",`Capping sequence numbers to collect down to the maximum of ${this.params.maximumSequenceNumbersToCollect} from ${t}`),r=this.params.maximumSequenceNumbersToCollect):r=t,s=Date.now(),this.nthSequenceNumber(e,r))).next(r=>(n=r,a=Date.now(),this.removeTargets(e,n,t))).next(t=>(i=t,o=Date.now(),this.removeOrphanedDocuments(e,n))).next(e=>(l=Date.now(),nq()<=f.in.DEBUG&&nj("LruGarbageCollector",`LRU Garbage Collection
	Counted targets in ${s-u}ms
	Determined least recently used ${r} in `+(a-s)+"ms\n"+`	Removed ${i} targets in `+(o-a)+"ms\n"+`	Removed ${e} documents in `+(l-o)+"ms\n"+`Total Duration: ${l-u}ms`),ry.resolve({didRun:!0,sequenceNumbersCollected:r,targetsRemoved:i,documentsRemoved:e})))}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class oS{constructor(e,t){this.db=e,this.garbageCollector=new oE(this,t)}Bn(e){let t=this.Un(e);return this.db.getTargetCache().getTargetCount(e).next(e=>t.next(t=>e+t))}Un(e){let t=0;return this.Ln(e,e=>{t++}).next(()=>t)}forEachTarget(e,t){return this.db.getTargetCache().forEachTarget(e,t)}Ln(e,t){return this.Kn(e,(e,n)=>t(n))}addReference(e,t,n){return ok(e,n)}removeReference(e,t,n){return ok(e,n)}removeTargets(e,t,n){return this.db.getTargetCache().removeTargets(e,t,n)}markPotentiallyOrphaned(e,t){return ok(e,t)}Gn(e,t){let n;return n=!1,om(e).tt(r=>od(e,r,t).next(e=>(e&&(n=!0),ry.resolve(!e)))).next(()=>n)}removeOrphanedDocuments(e,t){let n=this.db.getRemoteDocumentCache().newChangeBuffer(),r=[],i=0;return this.Kn(e,(s,a)=>{if(a<=t){let o=this.Gn(e,s).next(t=>{if(!t)return i++,n.getEntry(e,s).next(()=>(n.removeEntry(s,n7.min()),o_(e).delete([0,at(s.path)])))});r.push(o)}}).next(()=>ry.waitFor(r)).next(()=>n.apply(e)).next(()=>i)}removeTarget(e,t){let n=t.withSequenceNumber(e.currentSequenceNumber);return this.db.getTargetCache().updateTargetData(e,n)}updateLimboDocument(e,t){return ok(e,t)}Kn(e,t){let n=o_(e),r,i=rx.at;return n.Z({index:"documentTargetsIndex"},([e,n],{path:s,sequenceNumber:a})=>{0===e?(i!==rx.at&&t(new ri(an(r)),i),i=a,r=s):i=rx.at}).next(()=>{i!==rx.at&&t(new ri(an(r)),i)})}getCacheSize(e){return this.db.getRemoteDocumentCache().getSize(e)}}function ok(e,t){var n;return o_(e).put((n=e.currentSequenceNumber,{targetId:0,path:at(t.path),sequenceNumber:n}))}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class oA{constructor(){this.changes=new sb(e=>e.toString(),(e,t)=>e.isEqual(t)),this.changesApplied=!1}addEntry(e){this.assertNotApplied(),this.changes.set(e.key,e)}removeEntry(e,t){this.assertNotApplied(),this.changes.set(e,ix.newInvalidDocument(e).setReadTime(t))}getEntry(e,t){this.assertNotApplied();let n=this.changes.get(t);return void 0!==n?ry.resolve(n):this.getFromCache(e,t)}getEntries(e,t){return this.getAllFromCache(e,t)}apply(e){return this.assertNotApplied(),this.changesApplied=!0,this.applyChanges(e)}assertNotApplied(){}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class oC{constructor(e){this.yt=e}setIndexManager(e){this.indexManager=e}addEntry(e,t,n){return oD(e).put(n)}removeEntry(e,t,n){return oD(e).delete(function(e,t){let n=e.path.toArray();return[n.slice(0,n.length-2),n[n.length-2],aD(t),n[n.length-1]]}(t,n))}updateMetadata(e,t){return this.getMetadata(e).next(n=>(n.byteSize+=t,this.Qn(e,n)))}getEntry(e,t){let n=ix.newInvalidDocument(t);return oD(e).Z({index:"documentKeyIndex",range:IDBKeyRange.only(oN(t))},(e,r)=>{n=this.jn(t,r)}).next(()=>n)}Wn(e,t){let n={size:0,document:ix.newInvalidDocument(t)};return oD(e).Z({index:"documentKeyIndex",range:IDBKeyRange.only(oN(t))},(e,r)=>{n={document:this.jn(t,r),size:oc(r)}}).next(()=>n)}getEntries(e,t){let n=sI;return this.zn(e,t,(e,t)=>{let r=this.jn(e,t);n=n.insert(e,r)}).next(()=>n)}Hn(e,t){let n=sI,r=new ib(ri.comparator);return this.zn(e,t,(e,t)=>{let i=this.jn(e,t);n=n.insert(e,i),r=r.insert(e,oc(t))}).next(()=>({documents:n,Jn:r}))}zn(e,t,n){if(t.isEmpty())return ry.resolve();let r=new iE(oP);t.forEach(e=>r=r.add(e));let i=IDBKeyRange.bound(oN(r.first()),oN(r.last())),s=r.getIterator(),a=s.getNext();return oD(e).Z({index:"documentKeyIndex",range:i},(e,t,r)=>{let i=ri.fromSegments([...t.prefixPath,t.collectionGroup,t.documentId]);for(;a&&0>oP(a,i);)n(a,null),a=s.getNext();a&&a.isEqual(i)&&(n(a,t),a=s.hasNext()?s.getNext():null),a?r.j(oN(a)):r.done()}).next(()=>{for(;a;)n(a,null),a=s.hasNext()?s.getNext():null})}getAllFromCollection(e,t,n){let r=[t.popLast().toArray(),t.lastSegment(),aD(n.readTime),n.documentKey.path.isEmpty()?"":n.documentKey.path.lastSegment()],i=[t.popLast().toArray(),t.lastSegment(),[Number.MAX_SAFE_INTEGER,Number.MAX_SAFE_INTEGER],""];return oD(e).W(IDBKeyRange.bound(r,i,!0)).next(e=>{let t=sI;for(let n of e){let r=this.jn(ri.fromSegments(n.prefixPath.concat(n.collectionGroup,n.documentId)),n);t=t.insert(r.key,r)}return t})}getAllFromCollectionGroup(e,t,n,r){let i=sI,s=oO(t,n),a=oO(t,rd.max());return oD(e).Z({index:"collectionGroupIndex",range:IDBKeyRange.bound(s,a,!0)},(e,t,n)=>{let s=this.jn(ri.fromSegments(t.prefixPath.concat(t.collectionGroup,t.documentId)),t);(i=i.insert(s.key,s)).size===r&&n.done()}).next(()=>i)}newChangeBuffer(e){return new ox(this,!!e&&e.trackRemovals)}getSize(e){return this.getMetadata(e).next(e=>e.byteSize)}getMetadata(e){return oR(e).get("remoteDocumentGlobalKey").next(e=>(e||nK(),e))}Qn(e,t){return oR(e).put("remoteDocumentGlobalKey",t)}jn(e,t){if(t){let n=function(e,t){let n;if(t.document)n=s2(e.ie,t.document,!!t.hasCommittedMutations);else if(t.noDocument){let r=ri.fromSegments(t.noDocument.path),i=aO(t.noDocument.readTime);n=ix.newNoDocument(r,i),t.hasCommittedMutations&&n.setHasCommittedMutations()}else{if(!t.unknownDocument)return nK();{let s=ri.fromSegments(t.unknownDocument.path),a=aO(t.unknownDocument.version);n=ix.newUnknownDocument(s,a)}}return t.readTime&&n.setReadTime(function(e){let t=new n8(e[0],e[1]);return n7.fromTimestamp(t)}(t.readTime)),n}(this.yt,t);if(!(n.isNoDocument()&&n.version.isEqual(n7.min())))return n}return ix.newInvalidDocument(e)}}class ox extends oA{constructor(e,t){super(),this.Yn=e,this.trackRemovals=t,this.Xn=new sb(e=>e.toString(),(e,t)=>e.isEqual(t))}applyChanges(e){let t=[],n=0,r=new iE((e,t)=>n5(e.canonicalString(),t.canonicalString()));return this.changes.forEach((i,s)=>{let a=this.Xn.get(i);if(t.push(this.Yn.removeEntry(e,i,a.readTime)),s.isValidDocument()){let o=aR(this.Yn.yt,s);r=r.add(i.path.popLast());let l=oc(o);n+=l-a.size,t.push(this.Yn.addEntry(e,i,o))}else if(n-=a.size,this.trackRemovals){let u=aR(this.Yn.yt,s.convertToNoDocument(n7.min()));t.push(this.Yn.addEntry(e,i,u))}}),r.forEach(n=>{t.push(this.Yn.indexManager.addToCollectionParentIndex(e,n))}),t.push(this.Yn.updateMetadata(e,n)),ry.waitFor(t)}getFromCache(e,t){return this.Yn.Wn(e,t).next(e=>(this.Xn.set(t,{size:e.size,readTime:e.document.readTime}),e.document))}getAllFromCache(e,t){return this.Yn.Hn(e,t).next(({documents:e,Jn:t})=>(t.forEach((t,n)=>{this.Xn.set(t,{size:n,readTime:e.get(t).readTime})}),e))}}function oR(e){return aE(e,"remoteDocumentGlobal")}function oD(e){return aE(e,"remoteDocumentsV14")}function oN(e){let t=e.path.toArray();return[t.slice(0,t.length-2),t[t.length-2],t[t.length-1]]}function oO(e,t){let n=t.documentKey.path.toArray();return[e,aD(t.readTime),n.slice(0,n.length-2),n.length>0?n[n.length-1]:""]}function oP(e,t){let n=e.path.toArray(),r=t.path.toArray(),i=0;for(let s=0;s<n.length-2&&s<r.length-2;++s)if(i=n5(n[s],r[s]))return i;return(i=n5(n.length,r.length))||(i=n5(n[n.length-2],r[r.length-2]))||n5(n[n.length-1],r[r.length-1])}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *//**
 * @license
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class oL{constructor(e,t){this.overlayedDocument=e,this.mutatedFields=t}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class oM{constructor(e,t,n,r){this.remoteDocumentCache=e,this.mutationQueue=t,this.documentOverlayCache=n,this.indexManager=r}getDocument(e,t){let n=null;return this.documentOverlayCache.getOverlay(e,t).next(r=>(n=r,this.remoteDocumentCache.getEntry(e,t))).next(e=>(null!==n&&su(n.mutation,e,iA.empty(),n8.now()),e))}getDocuments(e,t){return this.remoteDocumentCache.getEntries(e,t).next(t=>this.getLocalViewOfDocuments(e,t,sx()).next(()=>t))}getLocalViewOfDocuments(e,t,n=sx()){let r=sk();return this.populateOverlays(e,r,t).next(()=>this.computeViews(e,t,r,n).next(e=>{let t=sE();return e.forEach((e,n)=>{t=t.insert(e,n.overlayedDocument)}),t}))}getOverlayedDocuments(e,t){let n=sk();return this.populateOverlays(e,n,t).next(()=>this.computeViews(e,t,n,sx()))}populateOverlays(e,t,n){let r=[];return n.forEach(e=>{t.has(e)||r.push(e)}),this.documentOverlayCache.getOverlays(e,r).next(e=>{e.forEach((e,n)=>{t.set(e,n)})})}computeViews(e,t,n,r){let i=sI,s=sk(),a=sk();return t.forEach((e,t)=>{let a=n.get(t.key);r.has(t.key)&&(void 0===a||a.mutation instanceof sd)?i=i.insert(t.key,t):void 0!==a&&(s.set(t.key,a.mutation.getFieldMask()),su(a.mutation,t,a.mutation.getFieldMask(),n8.now()))}),this.recalculateAndSaveOverlays(e,i).next(e=>(e.forEach((e,t)=>s.set(e,t)),t.forEach((e,t)=>{var n;return a.set(e,new oL(t,null!==(n=s.get(e))&&void 0!==n?n:null))}),a))}recalculateAndSaveOverlays(e,t){let n=sk(),r=new ib((e,t)=>e-t),i=sx();return this.mutationQueue.getAllMutationBatchesAffectingDocumentKeys(e,t).next(e=>{for(let i of e)i.keys().forEach(e=>{let s=t.get(e);if(null===s)return;let a=n.get(e)||iA.empty();a=i.applyToLocalView(s,a),n.set(e,a);let o=(r.get(i.batchId)||sx()).add(e);r=r.insert(i.batchId,o)})}).next(()=>{let s=[],a=r.getReverseIterator();for(;a.hasNext();){let o=a.getNext(),l=o.key,u=o.value,c=sk();u.forEach(e=>{if(!i.has(e)){let r=sl(t.get(e),n.get(e));null!==r&&c.set(e,r),i=i.add(e)}}),s.push(this.documentOverlayCache.saveOverlays(e,l,c))}return ry.waitFor(s)}).next(()=>n)}recalculateAndSaveOverlaysForDocumentKeys(e,t){return this.remoteDocumentCache.getEntries(e,t).next(t=>this.recalculateAndSaveOverlays(e,t))}getDocumentsMatchingQuery(e,t,n){return ri.isDocumentKey(t.path)&&null===t.collectionGroup&&0===t.filters.length?this.getDocumentsMatchingDocumentQuery(e,t.path):i$(t)?this.getDocumentsMatchingCollectionGroupQuery(e,t,n):this.getDocumentsMatchingCollectionQuery(e,t,n)}getNextDocuments(e,t,n,r){return this.remoteDocumentCache.getAllFromCollectionGroup(e,t,n,r).next(i=>{let s=r-i.size>0?this.documentOverlayCache.getOverlaysForCollectionGroup(e,t,n.largestBatchId,r-i.size):ry.resolve(sk()),a=-1,o=i;return s.next(t=>ry.forEach(t,(t,n)=>(a<n.largestBatchId&&(a=n.largestBatchId),i.get(t)?ry.resolve():this.remoteDocumentCache.getEntry(e,t).next(e=>{o=o.insert(t,e)}))).next(()=>this.populateOverlays(e,t,i)).next(()=>this.computeViews(e,o,t,sx())).next(e=>({batchId:a,changes:sS(e)})))})}getDocumentsMatchingDocumentQuery(e,t){return this.getDocument(e,new ri(t)).next(e=>{let t=sE();return e.isFoundDocument()&&(t=t.insert(e.key,e)),t})}getDocumentsMatchingCollectionGroupQuery(e,t,n){let r=t.collectionGroup,i=sE();return this.indexManager.getCollectionParents(e,r).next(s=>ry.forEach(s,s=>{var a;let o=(a=s.child(r),new iU(a,null,t.explicitOrderBy.slice(),t.filters.slice(),t.limit,t.limitType,t.startAt,t.endAt));return this.getDocumentsMatchingCollectionQuery(e,o,n).next(e=>{e.forEach((e,t)=>{i=i.insert(e,t)})})}).next(()=>i))}getDocumentsMatchingCollectionQuery(e,t,n){let r;return this.remoteDocumentCache.getAllFromCollection(e,t.path,n).next(i=>(r=i,this.documentOverlayCache.getOverlaysForCollection(e,t.path,n.largestBatchId))).next(e=>{e.forEach((e,t)=>{let n=t.getKey();null===r.get(n)&&(r=r.insert(n,ix.newInvalidDocument(n)))});let n=sE();return r.forEach((r,i)=>{let s=e.get(r);void 0!==s&&su(s.mutation,i,iA.empty(),n8.now()),iX(t,i)&&(n=n.insert(r,i))}),n})}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class oF{constructor(e){this.yt=e,this.Zn=new Map,this.ts=new Map}getBundleMetadata(e,t){return ry.resolve(this.Zn.get(t))}saveBundleMetadata(e,t){return this.Zn.set(t.id,{id:t.id,version:t.version,createTime:sK(t.createTime)}),ry.resolve()}getNamedQuery(e,t){return ry.resolve(this.ts.get(t))}saveNamedQuery(e,t){return this.ts.set(t.name,{name:t.name,query:aF(t.bundledQuery),readTime:sK(t.readTime)}),ry.resolve()}}/**
 * @license
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class oU{constructor(){this.overlays=new ib(ri.comparator),this.es=new Map}getOverlay(e,t){return ry.resolve(this.overlays.get(t))}getOverlays(e,t){let n=sk();return ry.forEach(t,t=>this.getOverlay(e,t).next(e=>{null!==e&&n.set(t,e)})).next(()=>n)}saveOverlays(e,t,n){return n.forEach((n,r)=>{this.oe(e,t,r)}),ry.resolve()}removeOverlaysForBatchId(e,t,n){let r=this.es.get(n);return void 0!==r&&(r.forEach(e=>this.overlays=this.overlays.remove(e)),this.es.delete(n)),ry.resolve()}getOverlaysForCollection(e,t,n){let r=sk(),i=t.length+1,s=new ri(t.child("")),a=this.overlays.getIteratorFrom(s);for(;a.hasNext();){let o=a.getNext().value,l=o.getKey();if(!t.isPrefixOf(l.path))break;l.path.length===i&&o.largestBatchId>n&&r.set(o.getKey(),o)}return ry.resolve(r)}getOverlaysForCollectionGroup(e,t,n,r){let i=new ib((e,t)=>e-t),s=this.overlays.getIterator();for(;s.hasNext();){let a=s.getNext().value;if(a.getKey().getCollectionGroup()===t&&a.largestBatchId>n){let o=i.get(a.largestBatchId);null===o&&(o=sk(),i=i.insert(a.largestBatchId,o)),o.set(a.getKey(),a)}}let l=sk(),u=i.getIterator();for(;u.hasNext()&&(u.getNext().value.forEach((e,t)=>l.set(e,t)),!(l.size()>=r)););return ry.resolve(l)}oe(e,t,n){let r=this.overlays.get(n.key);if(null!==r){let i=this.es.get(r.largestBatchId).delete(n.key);this.es.set(r.largestBatchId,i)}this.overlays=this.overlays.insert(n.key,new aA(t,n));let s=this.es.get(t);void 0===s&&(s=sx(),this.es.set(t,s)),this.es.set(t,s.add(n.key))}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class oV{constructor(){this.ns=new iE(oq.ss),this.rs=new iE(oq.os)}isEmpty(){return this.ns.isEmpty()}addReference(e,t){let n=new oq(e,t);this.ns=this.ns.add(n),this.rs=this.rs.add(n)}us(e,t){e.forEach(e=>this.addReference(e,t))}removeReference(e,t){this.cs(new oq(e,t))}hs(e,t){e.forEach(e=>this.removeReference(e,t))}ls(e){let t=new ri(new rt([])),n=new oq(t,e),r=new oq(t,e+1),i=[];return this.rs.forEachInRange([n,r],e=>{this.cs(e),i.push(e.key)}),i}fs(){this.ns.forEach(e=>this.cs(e))}cs(e){this.ns=this.ns.delete(e),this.rs=this.rs.delete(e)}ds(e){let t=new ri(new rt([])),n=new oq(t,e),r=new oq(t,e+1),i=sx();return this.rs.forEachInRange([n,r],e=>{i=i.add(e.key)}),i}containsKey(e){let t=new oq(e,0),n=this.ns.firstAfterOrEqual(t);return null!==n&&e.isEqual(n.key)}}class oq{constructor(e,t){this.key=e,this._s=t}static ss(e,t){return ri.comparator(e.key,t.key)||n5(e._s,t._s)}static os(e,t){return n5(e._s,t._s)||ri.comparator(e.key,t.key)}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class oB{constructor(e,t){this.indexManager=e,this.referenceDelegate=t,this.mutationQueue=[],this.ws=1,this.gs=new iE(oq.ss)}checkEmpty(e){return ry.resolve(0===this.mutationQueue.length)}addMutationBatch(e,t,n,r){let i=this.ws;this.ws++,this.mutationQueue.length>0&&this.mutationQueue[this.mutationQueue.length-1];let s=new aS(i,t,n,r);for(let a of(this.mutationQueue.push(s),r))this.gs=this.gs.add(new oq(a.key,i)),this.indexManager.addToCollectionParentIndex(e,a.key.path.popLast());return ry.resolve(s)}lookupMutationBatch(e,t){return ry.resolve(this.ys(t))}getNextMutationBatchAfterBatchId(e,t){let n=this.ps(t+1),r=n<0?0:n;return ry.resolve(this.mutationQueue.length>r?this.mutationQueue[r]:null)}getHighestUnacknowledgedBatchId(){return ry.resolve(0===this.mutationQueue.length?-1:this.ws-1)}getAllMutationBatches(e){return ry.resolve(this.mutationQueue.slice())}getAllMutationBatchesAffectingDocumentKey(e,t){let n=new oq(t,0),r=new oq(t,Number.POSITIVE_INFINITY),i=[];return this.gs.forEachInRange([n,r],e=>{let t=this.ys(e._s);i.push(t)}),ry.resolve(i)}getAllMutationBatchesAffectingDocumentKeys(e,t){let n=new iE(n5);return t.forEach(e=>{let t=new oq(e,0),r=new oq(e,Number.POSITIVE_INFINITY);this.gs.forEachInRange([t,r],e=>{n=n.add(e._s)})}),ry.resolve(this.Is(n))}getAllMutationBatchesAffectingQuery(e,t){let n=t.path,r=n.length+1,i=n;ri.isDocumentKey(i)||(i=i.child(""));let s=new oq(new ri(i),0),a=new iE(n5);return this.gs.forEachWhile(e=>{let t=e.key.path;return!!n.isPrefixOf(t)&&(t.length===r&&(a=a.add(e._s)),!0)},s),ry.resolve(this.Is(a))}Is(e){let t=[];return e.forEach(e=>{let n=this.ys(e);null!==n&&t.push(n)}),t}removeMutationBatch(e,t){0===this.Ts(t.batchId,"removed")||nK(),this.mutationQueue.shift();let n=this.gs;return ry.forEach(t.mutations,r=>{let i=new oq(r.key,t.batchId);return n=n.delete(i),this.referenceDelegate.markPotentiallyOrphaned(e,r.key)}).next(()=>{this.gs=n})}An(e){}containsKey(e,t){let n=new oq(t,0),r=this.gs.firstAfterOrEqual(n);return ry.resolve(t.isEqual(r&&r.key))}performConsistencyCheck(e){return this.mutationQueue.length,ry.resolve()}Ts(e,t){return this.ps(e)}ps(e){return 0===this.mutationQueue.length?0:e-this.mutationQueue[0].batchId}ys(e){let t=this.ps(e);return t<0||t>=this.mutationQueue.length?null:this.mutationQueue[t]}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class oj{constructor(e){this.Es=e,this.docs=new ib(ri.comparator),this.size=0}setIndexManager(e){this.indexManager=e}addEntry(e,t){let n=t.key,r=this.docs.get(n),i=r?r.size:0,s=this.Es(t);return this.docs=this.docs.insert(n,{document:t.mutableCopy(),size:s}),this.size+=s-i,this.indexManager.addToCollectionParentIndex(e,n.path.popLast())}removeEntry(e){let t=this.docs.get(e);t&&(this.docs=this.docs.remove(e),this.size-=t.size)}getEntry(e,t){let n=this.docs.get(t);return ry.resolve(n?n.document.mutableCopy():ix.newInvalidDocument(t))}getEntries(e,t){let n=sI;return t.forEach(e=>{let t=this.docs.get(e);n=n.insert(e,t?t.document.mutableCopy():ix.newInvalidDocument(e))}),ry.resolve(n)}getAllFromCollection(e,t,n){let r=sI,i=new ri(t.child("")),s=this.docs.getIteratorFrom(i);for(;s.hasNext();){let{key:a,value:{document:o}}=s.getNext();if(!t.isPrefixOf(a.path))break;a.path.length>t.length+1||0>=rf(rh(o),n)||(r=r.insert(o.key,o.mutableCopy()))}return ry.resolve(r)}getAllFromCollectionGroup(e,t,n,r){nK()}As(e,t){return ry.forEach(this.docs,e=>t(e))}newChangeBuffer(e){return new o$(this)}getSize(e){return ry.resolve(this.size)}}class o$ extends oA{constructor(e){super(),this.Yn=e}applyChanges(e){let t=[];return this.changes.forEach((n,r)=>{r.isValidDocument()?t.push(this.Yn.addEntry(e,r)):this.Yn.removeEntry(n)}),ry.waitFor(t)}getFromCache(e,t){return this.Yn.getEntry(e,t)}getAllFromCache(e,t){return this.Yn.getEntries(e,t)}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class oz{constructor(e){this.persistence=e,this.Rs=new sb(e=>iN(e),iO),this.lastRemoteSnapshotVersion=n7.min(),this.highestTargetId=0,this.bs=0,this.Ps=new oV,this.targetCount=0,this.vs=og.Pn()}forEachTarget(e,t){return this.Rs.forEach((e,n)=>t(n)),ry.resolve()}getLastRemoteSnapshotVersion(e){return ry.resolve(this.lastRemoteSnapshotVersion)}getHighestSequenceNumber(e){return ry.resolve(this.bs)}allocateTargetId(e){return this.highestTargetId=this.vs.next(),ry.resolve(this.highestTargetId)}setTargetsMetadata(e,t,n){return n&&(this.lastRemoteSnapshotVersion=n),t>this.bs&&(this.bs=t),ry.resolve()}Dn(e){this.Rs.set(e.target,e);let t=e.targetId;t>this.highestTargetId&&(this.vs=new og(t),this.highestTargetId=t),e.sequenceNumber>this.bs&&(this.bs=e.sequenceNumber)}addTargetData(e,t){return this.Dn(t),this.targetCount+=1,ry.resolve()}updateTargetData(e,t){return this.Dn(t),ry.resolve()}removeTargetData(e,t){return this.Rs.delete(t.target),this.Ps.ls(t.targetId),this.targetCount-=1,ry.resolve()}removeTargets(e,t,n){let r=0,i=[];return this.Rs.forEach((s,a)=>{a.sequenceNumber<=t&&null===n.get(a.targetId)&&(this.Rs.delete(s),i.push(this.removeMatchingKeysForTargetId(e,a.targetId)),r++)}),ry.waitFor(i).next(()=>r)}getTargetCount(e){return ry.resolve(this.targetCount)}getTargetData(e,t){let n=this.Rs.get(t)||null;return ry.resolve(n)}addMatchingKeys(e,t,n){return this.Ps.us(t,n),ry.resolve()}removeMatchingKeys(e,t,n){this.Ps.hs(t,n);let r=this.persistence.referenceDelegate,i=[];return r&&t.forEach(t=>{i.push(r.markPotentiallyOrphaned(e,t))}),ry.waitFor(i)}removeMatchingKeysForTargetId(e,t){return this.Ps.ls(t),ry.resolve()}getMatchingKeysForTargetId(e,t){let n=this.Ps.ds(t);return ry.resolve(n)}containsKey(e,t){return ry.resolve(this.Ps.containsKey(t))}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class oG{constructor(e,t){var n;this.Vs={},this.overlays={},this.Ss=new rx(0),this.Ds=!1,this.Ds=!0,this.referenceDelegate=e(this),this.Cs=new oz(this),this.indexManager=new a8,this.remoteDocumentCache=(n=e=>this.referenceDelegate.xs(e),new oj(n)),this.yt=new ax(t),this.Ns=new oF(this.yt)}start(){return Promise.resolve()}shutdown(){return this.Ds=!1,Promise.resolve()}get started(){return this.Ds}setDatabaseDeletedListener(){}setNetworkEnabled(){}getIndexManager(e){return this.indexManager}getDocumentOverlayCache(e){let t=this.overlays[e.toKey()];return t||(t=new oU,this.overlays[e.toKey()]=t),t}getMutationQueue(e,t){let n=this.Vs[e.toKey()];return n||(n=new oB(t,this.referenceDelegate),this.Vs[e.toKey()]=n),n}getTargetCache(){return this.Cs}getRemoteDocumentCache(){return this.remoteDocumentCache}getBundleCache(){return this.Ns}runTransaction(e,t,n){nj("MemoryPersistence","Starting transaction:",e);let r=new oK(this.Ss.next());return this.referenceDelegate.ks(),n(r).next(e=>this.referenceDelegate.Os(r).next(()=>e)).toPromise().then(e=>(r.raiseOnCommittedEvent(),e))}Ms(e,t){return ry.or(Object.values(this.Vs).map(n=>()=>n.containsKey(e,t)))}}class oK extends rm{constructor(e){super(),this.currentSequenceNumber=e}}class oH{constructor(e){this.persistence=e,this.Fs=new oV,this.$s=null}static Bs(e){return new oH(e)}get Ls(){if(this.$s)return this.$s;throw nK()}addReference(e,t,n){return this.Fs.addReference(n,t),this.Ls.delete(n.toString()),ry.resolve()}removeReference(e,t,n){return this.Fs.removeReference(n,t),this.Ls.add(n.toString()),ry.resolve()}markPotentiallyOrphaned(e,t){return this.Ls.add(t.toString()),ry.resolve()}removeTarget(e,t){this.Fs.ls(t.targetId).forEach(e=>this.Ls.add(e.toString()));let n=this.persistence.getTargetCache();return n.getMatchingKeysForTargetId(e,t.targetId).next(e=>{e.forEach(e=>this.Ls.add(e.toString()))}).next(()=>n.removeTargetData(e,t))}ks(){this.$s=new Set}Os(e){let t=this.persistence.getRemoteDocumentCache().newChangeBuffer();return ry.forEach(this.Ls,n=>{let r=ri.fromPath(n);return this.qs(e,r).next(e=>{e||t.removeEntry(r,n7.min())})}).next(()=>(this.$s=null,t.apply(e)))}updateLimboDocument(e,t){return this.qs(e,t).next(e=>{e?this.Ls.delete(t.toString()):this.Ls.add(t.toString())})}xs(e){return 0}qs(e,t){return ry.or([()=>ry.resolve(this.Fs.containsKey(t)),()=>this.persistence.getTargetCache().containsKey(e,t),()=>this.persistence.Ms(e,t)])}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class oW{constructor(e){this.yt=e}$(e,t,n,r){let i=new rv("createOrUpgrade",t);n<1&&r>=1&&(function(e){e.createObjectStore("owner")}(e),e.createObjectStore("mutationQueues",{keyPath:"userId"}),e.createObjectStore("mutations",{keyPath:"batchId",autoIncrement:!0}).createIndex("userMutationsIndex",ar,{unique:!0}),e.createObjectStore("documentMutations"),oQ(e),function(e){e.createObjectStore("remoteDocuments")}(e));let s=ry.resolve();return n<3&&r>=3&&(0!==n&&(e.deleteObjectStore("targetDocuments"),e.deleteObjectStore("targets"),e.deleteObjectStore("targetGlobal"),oQ(e)),s=s.next(()=>(function(e){let t=e.store("targetGlobal"),n={highestTargetId:0,highestListenSequenceNumber:0,lastRemoteSnapshotVersion:n7.min().toTimestamp(),targetCount:0};return t.put("targetGlobalKey",n)})(i))),n<4&&r>=4&&(0!==n&&(s=s.next(()=>i.store("mutations").W().next(t=>{e.deleteObjectStore("mutations"),e.createObjectStore("mutations",{keyPath:"batchId",autoIncrement:!0}).createIndex("userMutationsIndex",ar,{unique:!0});let n=i.store("mutations"),r=t.map(e=>n.put(e));return ry.waitFor(r)}))),s=s.next(()=>{!function(e){e.createObjectStore("clientMetadata",{keyPath:"clientId"})}(e)})),n<5&&r>=5&&(s=s.next(()=>this.Us(i))),n<6&&r>=6&&(s=s.next(()=>((function(e){e.createObjectStore("remoteDocumentGlobal")})(e),this.Ks(i)))),n<7&&r>=7&&(s=s.next(()=>this.Gs(i))),n<8&&r>=8&&(s=s.next(()=>this.Qs(e,i))),n<9&&r>=9&&(s=s.next(()=>{e.objectStoreNames.contains("remoteDocumentChanges")&&e.deleteObjectStore("remoteDocumentChanges")})),n<10&&r>=10&&(s=s.next(()=>this.js(i))),n<11&&r>=11&&(s=s.next(()=>{(function(e){e.createObjectStore("bundles",{keyPath:"bundleId"})})(e),function(e){e.createObjectStore("namedQueries",{keyPath:"name"})}(e)})),n<12&&r>=12&&(s=s.next(()=>{!function(e){let t=e.createObjectStore("documentOverlays",{keyPath:ag});t.createIndex("collectionPathOverlayIndex",ay,{unique:!1}),t.createIndex("collectionGroupOverlayIndex",av,{unique:!1})}(e)})),n<13&&r>=13&&(s=s.next(()=>(function(e){let t=e.createObjectStore("remoteDocumentsV14",{keyPath:as});t.createIndex("documentKeyIndex",aa),t.createIndex("collectionGroupIndex",ao)})(e)).next(()=>this.Ws(e,i)).next(()=>e.deleteObjectStore("remoteDocuments"))),n<14&&r>=14&&(s=s.next(()=>this.zs(e,i))),n<15&&r>=15&&(s=s.next(()=>{e.createObjectStore("indexConfiguration",{keyPath:"indexId",autoIncrement:!0}).createIndex("collectionGroupIndex","collectionGroup",{unique:!1}),e.createObjectStore("indexState",{keyPath:ad}).createIndex("sequenceNumberIndex",af,{unique:!1}),e.createObjectStore("indexEntries",{keyPath:ap}).createIndex("documentKeyIndex",am,{unique:!1})})),s}Ks(e){let t=0;return e.store("remoteDocuments").Z((e,n)=>{t+=oc(n)}).next(()=>{let n={byteSize:t};return e.store("remoteDocumentGlobal").put("remoteDocumentGlobalKey",n)})}Us(e){let t=e.store("mutationQueues"),n=e.store("mutations");return t.W().next(t=>ry.forEach(t,t=>{let r=IDBKeyRange.bound([t.userId,-1],[t.userId,t.lastAcknowledgedBatchId]);return n.W("userMutationsIndex",r).next(n=>ry.forEach(n,n=>{n.userId===t.userId||nK();let r=aP(this.yt,n);return ou(e,t.userId,r).next(()=>{})}))}))}Gs(e){let t=e.store("targetDocuments"),n=e.store("remoteDocuments");return e.store("targetGlobal").get("targetGlobalKey").next(e=>{let r=[];return n.Z((n,i)=>{let s=new rt(n),a=[0,at(s)];r.push(t.get(a).next(n=>n?ry.resolve():t.put({targetId:0,path:at(s),sequenceNumber:e.highestListenSequenceNumber})))}).next(()=>ry.waitFor(r))})}Qs(e,t){e.createObjectStore("collectionParents",{keyPath:ah});let n=t.store("collectionParents"),r=new a7,i=e=>{if(r.add(e)){let t=e.lastSegment(),i=e.popLast();return n.put({collectionId:t,parent:at(i)})}};return t.store("remoteDocuments").Z({X:!0},(e,t)=>{let n=new rt(e);return i(n.popLast())}).next(()=>t.store("documentMutations").Z({X:!0},([e,t,n],r)=>{let s=an(t);return i(s.popLast())}))}js(e){let t=e.store("targets");return t.Z((e,n)=>{let r=aL(n),i=aM(this.yt,r);return t.put(i)})}Ws(e,t){let n=t.store("remoteDocuments"),r=[];return n.Z((e,n)=>{let i=t.store("remoteDocumentsV14"),s=(n.document?new ri(rt.fromString(n.document.name).popFirst(5)):n.noDocument?ri.fromSegments(n.noDocument.path):n.unknownDocument?ri.fromSegments(n.unknownDocument.path):nK()).path.toArray(),a={prefixPath:s.slice(0,s.length-2),collectionGroup:s[s.length-2],documentId:s[s.length-1],readTime:n.readTime||[0,0],unknownDocument:n.unknownDocument,noDocument:n.noDocument,document:n.document,hasCommittedMutations:!!n.hasCommittedMutations};r.push(i.put(a))}).next(()=>ry.waitFor(r))}zs(e,t){var n;let r=t.store("mutations"),i=(n=this.yt,new oC(n)),s=new oG(oH.Bs,this.yt.ie);return r.W().next(e=>{let n=new Map;return e.forEach(e=>{var t;let r=null!==(t=n.get(e.userId))&&void 0!==t?t:sx();aP(this.yt,e).keys().forEach(e=>r=r.add(e)),n.set(e.userId,r)}),ry.forEach(n,(e,n)=>{let r=new nF(n),a=az.re(this.yt,r),o=s.getIndexManager(r),l=oh.re(r,this.yt,o,s.referenceDelegate);return new oM(i,l,a,o).recalculateAndSaveOverlaysForDocumentKeys(new aT(t,rx.at),e).next()})})}}function oQ(e){e.createObjectStore("targetDocuments",{keyPath:au}).createIndex("documentTargetsIndex",ac,{unique:!0}),e.createObjectStore("targets",{keyPath:"targetId"}).createIndex("queryTargetsIndex",al,{unique:!0}),e.createObjectStore("targetGlobal")}let oY="Failed to obtain exclusive access to the persistence layer. To allow shared access, multi-tab synchronization has to be enabled in all tabs. If you are using `experimentalForceOwningTab:true`, make sure that only one tab has persistence enabled at any given time.";class oX{constructor(e,t,n,r,i,s,a,o,l,u,c=15){var h;if(this.allowTabSynchronization=e,this.persistenceKey=t,this.clientId=n,this.Hs=i,this.window=s,this.document=a,this.Js=l,this.Ys=u,this.Xs=c,this.Ss=null,this.Ds=!1,this.isPrimary=!1,this.networkEnabled=!0,this.Zs=null,this.inForeground=!1,this.ti=null,this.ei=null,this.ni=Number.NEGATIVE_INFINITY,this.si=e=>Promise.resolve(),!oX.C())throw new nQ(nW.UNIMPLEMENTED,"This platform is either missing IndexedDB or is known to have an incomplete implementation. Offline persistence has been disabled.");this.referenceDelegate=new oS(this,r),this.ii=t+"main",this.yt=new ax(o),this.ri=new rw(this.ii,this.Xs,new oW(this.yt)),this.Cs=new oy(this.referenceDelegate,this.yt),this.remoteDocumentCache=(h=this.yt,new oC(h)),this.Ns=new aB,this.window&&this.window.localStorage?this.oi=this.window.localStorage:(this.oi=null,!1===u&&n$("IndexedDbPersistence","LocalStorage is unavailable. As a result, persistence may not work reliably. In particular enablePersistence() could fail immediately after refreshing the page."))}start(){return this.ui().then(()=>{if(!this.isPrimary&&!this.allowTabSynchronization)throw new nQ(nW.FAILED_PRECONDITION,oY);return this.ci(),this.ai(),this.hi(),this.runTransaction("getHighestListenSequenceNumber","readonly",e=>this.Cs.getHighestSequenceNumber(e))}).then(e=>{this.Ss=new rx(e,this.Js)}).then(()=>{this.Ds=!0}).catch(e=>(this.ri&&this.ri.close(),Promise.reject(e)))}li(e){return this.si=async t=>{if(this.started)return e(t)},e(this.isPrimary)}setDatabaseDeletedListener(e){this.ri.L(async t=>{null===t.newVersion&&await e()})}setNetworkEnabled(e){this.networkEnabled!==e&&(this.networkEnabled=e,this.Hs.enqueueAndForget(async()=>{this.started&&await this.ui()}))}ui(){return this.runTransaction("updateClientMetadataAndTryBecomePrimary","readwrite",e=>oZ(e).put({clientId:this.clientId,updateTimeMs:Date.now(),networkEnabled:this.networkEnabled,inForeground:this.inForeground}).next(()=>{if(this.isPrimary)return this.fi(e).next(e=>{e||(this.isPrimary=!1,this.Hs.enqueueRetryable(()=>this.si(!1)))})}).next(()=>this.di(e)).next(t=>this.isPrimary&&!t?this._i(e).next(()=>!1):!!t&&this.wi(e).next(()=>!0))).catch(e=>{if(rI(e))return nj("IndexedDbPersistence","Failed to extend owner lease: ",e),this.isPrimary;if(!this.allowTabSynchronization)throw e;return nj("IndexedDbPersistence","Releasing owner lease after error during lease refresh",e),!1}).then(e=>{this.isPrimary!==e&&this.Hs.enqueueRetryable(()=>this.si(e)),this.isPrimary=e})}fi(e){return oJ(e).get("owner").next(e=>ry.resolve(this.mi(e)))}gi(e){return oZ(e).delete(this.clientId)}async yi(){if(this.isPrimary&&!this.pi(this.ni,18e5)){this.ni=Date.now();let e=await this.runTransaction("maybeGarbageCollectMultiClientState","readwrite-primary",e=>{let t=aE(e,"clientMetadata");return t.W().next(e=>{let n=this.Ii(e,18e5),r=e.filter(e=>-1===n.indexOf(e));return ry.forEach(r,e=>t.delete(e.clientId)).next(()=>r)})}).catch(()=>[]);if(this.oi)for(let t of e)this.oi.removeItem(this.Ti(t.clientId))}}hi(){this.ei=this.Hs.enqueueAfterDelay("client_metadata_refresh",4e3,()=>this.ui().then(()=>this.yi()).then(()=>this.hi()))}mi(e){return!!e&&e.ownerId===this.clientId}di(e){return this.Ys?ry.resolve(!0):oJ(e).get("owner").next(t=>{if(null!==t&&this.pi(t.leaseTimestampMs,5e3)&&!this.Ei(t.ownerId)){if(this.mi(t)&&this.networkEnabled)return!0;if(!this.mi(t)){if(!t.allowTabSynchronization)throw new nQ(nW.FAILED_PRECONDITION,oY);return!1}}return!(!this.networkEnabled||!this.inForeground)||oZ(e).W().next(e=>void 0===this.Ii(e,5e3).find(e=>{if(this.clientId!==e.clientId){let t=!this.networkEnabled&&e.networkEnabled,n=!this.inForeground&&e.inForeground,r=this.networkEnabled===e.networkEnabled;if(t||n&&r)return!0}return!1}))}).next(e=>(this.isPrimary!==e&&nj("IndexedDbPersistence",`Client ${e?"is":"is not"} eligible for a primary lease.`),e))}async shutdown(){this.Ds=!1,this.Ai(),this.ei&&(this.ei.cancel(),this.ei=null),this.Ri(),this.bi(),await this.ri.runTransaction("shutdown","readwrite",["owner","clientMetadata"],e=>{let t=new aT(e,rx.at);return this._i(t).next(()=>this.gi(t))}),this.ri.close(),this.Pi()}Ii(e,t){return e.filter(e=>this.pi(e.updateTimeMs,t)&&!this.Ei(e.clientId))}vi(){return this.runTransaction("getActiveClients","readonly",e=>oZ(e).W().next(e=>this.Ii(e,18e5).map(e=>e.clientId)))}get started(){return this.Ds}getMutationQueue(e,t){return oh.re(e,this.yt,t,this.referenceDelegate)}getTargetCache(){return this.Cs}getRemoteDocumentCache(){return this.remoteDocumentCache}getIndexManager(e){return new ot(e,this.yt.ie.databaseId)}getDocumentOverlayCache(e){return az.re(this.yt,e)}getBundleCache(){return this.Ns}runTransaction(e,t,n){var r;let i;nj("IndexedDbPersistence","Starting transaction:",e);let s=15===(r=this.Xs)?aI:14===r?ab:13===r?ab:12===r?a_:11===r?aw:void nK();return this.ri.runTransaction(e,"readonly"===t?"readonly":"readwrite",s,r=>(i=new aT(r,this.Ss?this.Ss.next():rx.at),"readwrite-primary"===t?this.fi(i).next(e=>!!e||this.di(i)).next(t=>{if(!t)throw n$(`Failed to obtain primary lease for action '${e}'.`),this.isPrimary=!1,this.Hs.enqueueRetryable(()=>this.si(!1)),new nQ(nW.FAILED_PRECONDITION,rp);return n(i)}).next(e=>this.wi(i).next(()=>e)):this.Vi(i).next(()=>n(i)))).then(e=>(i.raiseOnCommittedEvent(),e))}Vi(e){return oJ(e).get("owner").next(e=>{if(null!==e&&this.pi(e.leaseTimestampMs,5e3)&&!this.Ei(e.ownerId)&&!this.mi(e)&&!(this.Ys||this.allowTabSynchronization&&e.allowTabSynchronization))throw new nQ(nW.FAILED_PRECONDITION,oY)})}wi(e){let t={ownerId:this.clientId,allowTabSynchronization:this.allowTabSynchronization,leaseTimestampMs:Date.now()};return oJ(e).put("owner",t)}static C(){return rw.C()}_i(e){let t=oJ(e);return t.get("owner").next(e=>this.mi(e)?(nj("IndexedDbPersistence","Releasing primary lease."),t.delete("owner")):ry.resolve())}pi(e,t){let n=Date.now();return!(e<n-t)&&(!(e>n)||(n$(`Detected an update time that is in the future: ${e} > ${n}`),!1))}ci(){null!==this.document&&"function"==typeof this.document.addEventListener&&(this.ti=()=>{this.Hs.enqueueAndForget(()=>(this.inForeground="visible"===this.document.visibilityState,this.ui()))},this.document.addEventListener("visibilitychange",this.ti),this.inForeground="visible"===this.document.visibilityState)}Ri(){this.ti&&(this.document.removeEventListener("visibilitychange",this.ti),this.ti=null)}ai(){var e;"function"==typeof(null===(e=this.window)||void 0===e?void 0:e.addEventListener)&&(this.Zs=()=>{this.Ai(),(0,p.G6)()&&navigator.appVersion.match(/Version\/1[45]/)&&this.Hs.enterRestrictedMode(!0),this.Hs.enqueueAndForget(()=>this.shutdown())},this.window.addEventListener("pagehide",this.Zs))}bi(){this.Zs&&(this.window.removeEventListener("pagehide",this.Zs),this.Zs=null)}Ei(e){var t;try{let n=null!==(null===(t=this.oi)||void 0===t?void 0:t.getItem(this.Ti(e)));return nj("IndexedDbPersistence",`Client '${e}' ${n?"is":"is not"} zombied in LocalStorage`),n}catch(r){return n$("IndexedDbPersistence","Failed to get zombied client id.",r),!1}}Ai(){if(this.oi)try{this.oi.setItem(this.Ti(this.clientId),String(Date.now()))}catch(e){n$("Failed to set zombie client id.",e)}}Pi(){if(this.oi)try{this.oi.removeItem(this.Ti(this.clientId))}catch(e){}}Ti(e){return`firestore_zombie_${this.persistenceKey}_${e}`}}function oJ(e){return aE(e,"owner")}function oZ(e){return aE(e,"clientMetadata")}function o0(e,t){let n=e.projectId;return e.isDefaultDatabase||(n+="."+e.database),"firestore/"+t+"/"+n+"/"}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class o1{constructor(e,t,n,r){this.targetId=e,this.fromCache=t,this.Si=n,this.Di=r}static Ci(e,t){let n=sx(),r=sx();for(let i of t.docChanges)switch(i.type){case 0:n=n.add(i.doc.key);break;case 1:r=r.add(i.doc.key)}return new o1(e,t.fromCache,n,r)}}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class o2{constructor(){this.xi=!1}initialize(e,t){this.Ni=e,this.indexManager=t,this.xi=!0}getDocumentsMatchingQuery(e,t,n,r){return this.ki(e,t).next(i=>i||this.Oi(e,t,r,n)).next(n=>n||this.Mi(e,t))}ki(e,t){if(iq(t))return ry.resolve(null);let n=iG(t);return this.indexManager.getIndexType(e,n).next(r=>0===r?null:(null!==t.limit&&1===r&&(n=iG(t=iH(t,null,"F"))),this.indexManager.getDocumentsMatchingTarget(e,n).next(r=>{let i=sx(...r);return this.Ni.getDocuments(e,i).next(r=>this.indexManager.getMinOffset(e,n).next(n=>{let s=this.Fi(t,r);return this.$i(t,s,i,n.readTime)?this.ki(e,iH(t,null,"F")):this.Bi(e,s,t,n)}))})))}Oi(e,t,n,r){return iq(t)||r.isEqual(n7.min())?this.Mi(e,t):this.Ni.getDocuments(e,n).next(i=>{let s=this.Fi(t,i);return this.$i(t,s,n,r)?this.Mi(e,t):(nq()<=f.in.DEBUG&&nj("QueryEngine","Re-using previous result from %s to execute query: %s",r.toString(),iY(t)),this.Bi(e,s,t,rc(r,-1)))})}Fi(e,t){let n=new iE(iZ(e));return t.forEach((t,r)=>{iX(e,r)&&(n=n.add(r))}),n}$i(e,t,n,r){if(null===e.limit)return!1;if(n.size!==t.size)return!0;let i="F"===e.limitType?t.last():t.first();return!!i&&(i.hasPendingWrites||i.version.compareTo(r)>0)}Mi(e,t){return nq()<=f.in.DEBUG&&nj("QueryEngine","Using full collection scan to execute query:",iY(t)),this.Ni.getDocumentsMatchingQuery(e,t,rd.min())}Bi(e,t,n,r){return this.Ni.getDocumentsMatchingQuery(e,n,r).next(e=>(t.forEach(t=>{e=e.insert(t.key,t)}),e))}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class o4{constructor(e,t,n,r){this.persistence=e,this.Li=t,this.yt=r,this.qi=new ib(n5),this.Ui=new sb(e=>iN(e),iO),this.Ki=new Map,this.Gi=e.getRemoteDocumentCache(),this.Cs=e.getTargetCache(),this.Ns=e.getBundleCache(),this.Qi(n)}Qi(e){this.documentOverlayCache=this.persistence.getDocumentOverlayCache(e),this.indexManager=this.persistence.getIndexManager(e),this.mutationQueue=this.persistence.getMutationQueue(e,this.indexManager),this.localDocuments=new oM(this.Gi,this.mutationQueue,this.documentOverlayCache,this.indexManager),this.Gi.setIndexManager(this.indexManager),this.Li.initialize(this.localDocuments,this.indexManager)}collectGarbage(e){return this.persistence.runTransaction("Collect garbage","readwrite-primary",t=>e.collect(t,this.qi))}}async function o3(e,t){return await e.persistence.runTransaction("Handle user change","readonly",n=>{let r;return e.mutationQueue.getAllMutationBatches(n).next(i=>(r=i,e.Qi(t),e.mutationQueue.getAllMutationBatches(n))).next(t=>{let i=[],s=[],a=sx();for(let o of r)for(let l of(i.push(o.batchId),o.mutations))a=a.add(l.key);for(let u of t)for(let c of(s.push(u.batchId),u.mutations))a=a.add(c.key);return e.localDocuments.getDocuments(n,a).next(e=>({ji:e,removedBatchIds:i,addedBatchIds:s}))})})}function o6(e){return e.persistence.runTransaction("Get last remote snapshot version","readonly",t=>e.Cs.getLastRemoteSnapshotVersion(t))}function o5(e,t,n){let r=sx(),i=sx();return n.forEach(e=>r=r.add(e)),t.getEntries(e,r).next(e=>{let r=sI;return n.forEach((n,s)=>{let a=e.get(n);s.isFoundDocument()!==a.isFoundDocument()&&(i=i.add(n)),s.isNoDocument()&&s.version.isEqual(n7.min())?(t.removeEntry(n,s.readTime),r=r.insert(n,s)):!a.isValidDocument()||s.version.compareTo(a.version)>0||0===s.version.compareTo(a.version)&&a.hasPendingWrites?(t.addEntry(s),r=r.insert(n,s)):nj("LocalStore","Ignoring outdated watch update for ",n,". Current version:",a.version," Watch version:",s.version)}),{Wi:r,zi:i}})}function o9(e,t){let n=e;return n.persistence.runTransaction("Allocate target","readwrite",e=>{let r;return n.Cs.getTargetData(e,t).next(i=>i?(r=i,ry.resolve(r)):n.Cs.allocateTargetId(e).next(i=>(r=new aC(t,i,0,e.currentSequenceNumber),n.Cs.addTargetData(e,r).next(()=>r))))}).then(e=>{let r=n.qi.get(e.targetId);return(null===r||e.snapshotVersion.compareTo(r.snapshotVersion)>0)&&(n.qi=n.qi.insert(e.targetId,e),n.Ui.set(t,e.targetId)),e})}async function o8(e,t,n){let r=e,i=r.qi.get(t);try{n||await r.persistence.runTransaction("Release target",n?"readwrite":"readwrite-primary",e=>r.persistence.referenceDelegate.removeTarget(e,i))}catch(s){if(!rI(s))throw s;nj("LocalStore",`Failed to update sequence numbers for target ${t}: ${s}`)}r.qi=r.qi.remove(t),r.Ui.delete(i.target)}function o7(e,t,n){let r=n7.min(),i=sx();return e.persistence.runTransaction("Execute query","readonly",s=>(function(e,t,n){let r=e.Ui.get(n);return void 0!==r?ry.resolve(e.qi.get(r)):e.Cs.getTargetData(t,n)})(e,s,iG(t)).next(t=>{if(t)return r=t.lastLimboFreeSnapshotVersion,e.Cs.getMatchingKeysForTargetId(s,t.targetId).next(e=>{i=e})}).next(()=>e.Li.getDocumentsMatchingQuery(s,t,n?r:n7.min(),n?i:sx())).next(n=>(ln(e,iJ(t),n),{documents:n,Hi:i})))}function le(e,t){let n=e.Cs,r=e.qi.get(t);return r?Promise.resolve(r.target):e.persistence.runTransaction("Get target data","readonly",e=>n.ne(e,t).next(e=>e?e.target:null))}function lt(e,t){let n=e.Ki.get(t)||n7.min();return e.persistence.runTransaction("Get new document changes","readonly",r=>e.Gi.getAllFromCollectionGroup(r,t,rc(n,-1),Number.MAX_SAFE_INTEGER)).then(n=>(ln(e,t,n),n))}function ln(e,t,n){let r=e.Ki.get(t)||n7.min();n.forEach((e,t)=>{t.readTime.compareTo(r)>0&&(r=t.readTime)}),e.Ki.set(t,r)}async function lr(e,t,n,r){let i=sx(),s=sI;for(let a of n){let o=t.Ji(a.metadata.name);a.document&&(i=i.add(o));let l=t.Yi(a);l.setReadTime(t.Xi(a.metadata.readTime)),s=s.insert(o,l)}let u=e.Gi.newChangeBuffer({trackRemovals:!0}),c=await o9(e,iG(iV(rt.fromString(`__bundle__/docs/${r}`))));return e.persistence.runTransaction("Apply bundle documents","readwrite",t=>o5(t,u,s).next(e=>(u.apply(t),e)).next(n=>e.Cs.removeMatchingKeysForTargetId(t,c.targetId).next(()=>e.Cs.addMatchingKeys(t,i,c.targetId)).next(()=>e.localDocuments.getLocalViewOfDocuments(t,n.Wi,n.zi)).next(()=>n.Wi)))}async function li(e,t,n=sx()){let r=await o9(e,iG(aF(t.bundledQuery))),i=e;return i.persistence.runTransaction("Save named query","readwrite",e=>{let s=sK(t.readTime);if(r.snapshotVersion.compareTo(s)>=0)return i.Ns.saveNamedQuery(e,t);let a=r.withResumeToken(rV.EMPTY_BYTE_STRING,s);return i.qi=i.qi.insert(a.targetId,a),i.Cs.updateTargetData(e,a).next(()=>i.Cs.removeMatchingKeysForTargetId(e,r.targetId)).next(()=>i.Cs.addMatchingKeys(e,n,r.targetId)).next(()=>i.Ns.saveNamedQuery(e,t))})}function ls(e,t){return`firestore_clients_${e}_${t}`}function la(e,t,n){let r=`firestore_mutations_${e}_${n}`;return t.isAuthenticated()&&(r+=`_${t.uid}`),r}function lo(e,t){return`firestore_targets_${e}_${t}`}class ll{constructor(e,t,n,r){this.user=e,this.batchId=t,this.state=n,this.error=r}static Zi(e,t,n){let r=JSON.parse(n),i,s="object"==typeof r&&-1!==["pending","acknowledged","rejected"].indexOf(r.state)&&(void 0===r.error||"object"==typeof r.error);return s&&r.error&&(s="string"==typeof r.error.message&&"string"==typeof r.error.code)&&(i=new nQ(r.error.code,r.error.message)),s?new ll(e,t,r.state,i):(n$("SharedClientState",`Failed to parse mutation state for ID '${t}': ${n}`),null)}tr(){let e={state:this.state,updateTimeMs:Date.now()};return this.error&&(e.error={code:this.error.code,message:this.error.message}),JSON.stringify(e)}}class lu{constructor(e,t,n){this.targetId=e,this.state=t,this.error=n}static Zi(e,t){let n=JSON.parse(t),r,i="object"==typeof n&&-1!==["not-current","current","rejected"].indexOf(n.state)&&(void 0===n.error||"object"==typeof n.error);return i&&n.error&&(i="string"==typeof n.error.message&&"string"==typeof n.error.code)&&(r=new nQ(n.error.code,n.error.message)),i?new lu(e,n.state,r):(n$("SharedClientState",`Failed to parse target state for ID '${e}': ${t}`),null)}tr(){let e={state:this.state,updateTimeMs:Date.now()};return this.error&&(e.error={code:this.error.code,message:this.error.message}),JSON.stringify(e)}}class lc{constructor(e,t){this.clientId=e,this.activeTargetIds=t}static Zi(e,t){let n=JSON.parse(t),r="object"==typeof n&&n.activeTargetIds instanceof Array,i=sR;for(let s=0;r&&s<n.activeTargetIds.length;++s)r=rF(n.activeTargetIds[s]),i=i.add(n.activeTargetIds[s]);return r?new lc(e,i):(n$("SharedClientState",`Failed to parse client data for instance '${e}': ${t}`),null)}}class lh{constructor(e,t){this.clientId=e,this.onlineState=t}static Zi(e){let t=JSON.parse(e);return"object"==typeof t&&-1!==["Unknown","Online","Offline"].indexOf(t.onlineState)&&"string"==typeof t.clientId?new lh(t.clientId,t.onlineState):(n$("SharedClientState",`Failed to parse online state: ${e}`),null)}}class ld{constructor(){this.activeTargetIds=sR}er(e){this.activeTargetIds=this.activeTargetIds.add(e)}nr(e){this.activeTargetIds=this.activeTargetIds.delete(e)}tr(){let e={activeTargetIds:this.activeTargetIds.toArray(),updateTimeMs:Date.now()};return JSON.stringify(e)}}class lf{constructor(e,t,n,r,i){this.window=e,this.Hs=t,this.persistenceKey=n,this.sr=r,this.syncEngine=null,this.onlineStateHandler=null,this.sequenceNumberHandler=null,this.ir=this.rr.bind(this),this.ur=new ib(n5),this.started=!1,this.cr=[];let s=n.replace(/[.*+?^${}()|[\]\\]/g,"\\$&");this.storage=this.window.localStorage,this.currentUser=i,this.ar=ls(this.persistenceKey,this.sr),this.hr=`firestore_sequence_number_${this.persistenceKey}`,this.ur=this.ur.insert(this.sr,new ld),this.lr=RegExp(`^firestore_clients_${s}_([^_]*)$`),this.dr=RegExp(`^firestore_mutations_${s}_(\\d+)(?:_(.*))?$`),this._r=RegExp(`^firestore_targets_${s}_(\\d+)$`),this.wr=`firestore_online_state_${this.persistenceKey}`,this.mr=`firestore_bundle_loaded_v2_${this.persistenceKey}`,this.window.addEventListener("storage",this.ir)}static C(e){return!(!e||!e.localStorage)}async start(){let e=await this.syncEngine.vi();for(let t of e){if(t===this.sr)continue;let n=this.getItem(ls(this.persistenceKey,t));if(n){let r=lc.Zi(t,n);r&&(this.ur=this.ur.insert(r.clientId,r))}}this.gr();let i=this.storage.getItem(this.wr);if(i){let s=this.yr(i);s&&this.pr(s)}for(let a of this.cr)this.rr(a);this.cr=[],this.window.addEventListener("pagehide",()=>this.shutdown()),this.started=!0}writeSequenceNumber(e){this.setItem(this.hr,JSON.stringify(e))}getAllActiveQueryTargets(){return this.Ir(this.ur)}isActiveQueryTarget(e){let t=!1;return this.ur.forEach((n,r)=>{r.activeTargetIds.has(e)&&(t=!0)}),t}addPendingMutation(e){this.Tr(e,"pending")}updateMutationState(e,t,n){this.Tr(e,t,n),this.Er(e)}addLocalQueryTarget(e){let t="not-current";if(this.isActiveQueryTarget(e)){let n=this.storage.getItem(lo(this.persistenceKey,e));if(n){let r=lu.Zi(e,n);r&&(t=r.state)}}return this.Ar.er(e),this.gr(),t}removeLocalQueryTarget(e){this.Ar.nr(e),this.gr()}isLocalQueryTarget(e){return this.Ar.activeTargetIds.has(e)}clearQueryState(e){this.removeItem(lo(this.persistenceKey,e))}updateQueryState(e,t,n){this.Rr(e,t,n)}handleUserChange(e,t,n){t.forEach(e=>{this.Er(e)}),this.currentUser=e,n.forEach(e=>{this.addPendingMutation(e)})}setOnlineState(e){this.br(e)}notifyBundleLoaded(e){this.Pr(e)}shutdown(){this.started&&(this.window.removeEventListener("storage",this.ir),this.removeItem(this.ar),this.started=!1)}getItem(e){let t=this.storage.getItem(e);return nj("SharedClientState","READ",e,t),t}setItem(e,t){nj("SharedClientState","SET",e,t),this.storage.setItem(e,t)}removeItem(e){nj("SharedClientState","REMOVE",e),this.storage.removeItem(e)}rr(e){if(e.storageArea===this.storage){if(nj("SharedClientState","EVENT",e.key,e.newValue),e.key===this.ar)return void n$("Received WebStorage notification for local change. Another client might have garbage-collected our state");this.Hs.enqueueRetryable(async()=>{if(this.started){if(null!==e.key){if(this.lr.test(e.key)){if(null==e.newValue){let t=this.vr(e.key);return this.Vr(t,null)}{let n=this.Sr(e.key,e.newValue);if(n)return this.Vr(n.clientId,n)}}else if(this.dr.test(e.key)){if(null!==e.newValue){let r=this.Dr(e.key,e.newValue);if(r)return this.Cr(r)}}else if(this._r.test(e.key)){if(null!==e.newValue){let i=this.Nr(e.key,e.newValue);if(i)return this.kr(i)}}else if(e.key===this.wr){if(null!==e.newValue){let s=this.yr(e.newValue);if(s)return this.pr(s)}}else if(e.key===this.hr){let a=function(e){let t=rx.at;if(null!=e)try{let n=JSON.parse(e);"number"==typeof n||nK(),t=n}catch(r){n$("SharedClientState","Failed to read sequence number from WebStorage",r)}return t}(e.newValue);a!==rx.at&&this.sequenceNumberHandler(a)}else if(e.key===this.mr){let o=this.Or(e.newValue);await Promise.all(o.map(e=>this.syncEngine.Mr(e)))}}}else this.cr.push(e)})}}get Ar(){return this.ur.get(this.sr)}gr(){this.setItem(this.ar,this.Ar.tr())}Tr(e,t,n){let r=new ll(this.currentUser,e,t,n),i=la(this.persistenceKey,this.currentUser,e);this.setItem(i,r.tr())}Er(e){let t=la(this.persistenceKey,this.currentUser,e);this.removeItem(t)}br(e){let t={clientId:this.sr,onlineState:e};this.storage.setItem(this.wr,JSON.stringify(t))}Rr(e,t,n){let r=lo(this.persistenceKey,e),i=new lu(e,t,n);this.setItem(r,i.tr())}Pr(e){let t=JSON.stringify(Array.from(e));this.setItem(this.mr,t)}vr(e){let t=this.lr.exec(e);return t?t[1]:null}Sr(e,t){let n=this.vr(e);return lc.Zi(n,t)}Dr(e,t){let n=this.dr.exec(e),r=Number(n[1]),i=void 0!==n[2]?n[2]:null;return ll.Zi(new nF(i),r,t)}Nr(e,t){let n=this._r.exec(e),r=Number(n[1]);return lu.Zi(r,t)}yr(e){return lh.Zi(e)}Or(e){return JSON.parse(e)}async Cr(e){if(e.user.uid===this.currentUser.uid)return this.syncEngine.Fr(e.batchId,e.state,e.error);nj("SharedClientState",`Ignoring mutation for non-active user ${e.user.uid}`)}kr(e){return this.syncEngine.$r(e.targetId,e.state,e.error)}Vr(e,t){let n=t?this.ur.insert(e,t):this.ur.remove(e),r=this.Ir(this.ur),i=this.Ir(n),s=[],a=[];return i.forEach(e=>{r.has(e)||s.push(e)}),r.forEach(e=>{i.has(e)||a.push(e)}),this.syncEngine.Br(s,a).then(()=>{this.ur=n})}pr(e){this.ur.get(e.clientId)&&this.onlineStateHandler(e.onlineState)}Ir(e){let t=sR;return e.forEach((e,n)=>{t=t.unionWith(n.activeTargetIds)}),t}}class lp{constructor(){this.Lr=new ld,this.qr={},this.onlineStateHandler=null,this.sequenceNumberHandler=null}addPendingMutation(e){}updateMutationState(e,t,n){}addLocalQueryTarget(e){return this.Lr.er(e),this.qr[e]||"not-current"}updateQueryState(e,t,n){this.qr[e]=t}removeLocalQueryTarget(e){this.Lr.nr(e)}isLocalQueryTarget(e){return this.Lr.activeTargetIds.has(e)}clearQueryState(e){delete this.qr[e]}getAllActiveQueryTargets(){return this.Lr.activeTargetIds}isActiveQueryTarget(e){return this.Lr.activeTargetIds.has(e)}start(){return this.Lr=new ld,Promise.resolve()}handleUserChange(e,t,n){}setOnlineState(e){}shutdown(){}writeSequenceNumber(e){}notifyBundleLoaded(e){}}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class lm{Ur(e){}shutdown(){}}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class lg{constructor(){this.Kr=()=>this.Gr(),this.Qr=()=>this.jr(),this.Wr=[],this.zr()}Ur(e){this.Wr.push(e)}shutdown(){window.removeEventListener("online",this.Kr),window.removeEventListener("offline",this.Qr)}zr(){window.addEventListener("online",this.Kr),window.addEventListener("offline",this.Qr)}Gr(){for(let e of(nj("ConnectivityMonitor","Network connectivity changed: AVAILABLE"),this.Wr))e(0)}jr(){for(let e of(nj("ConnectivityMonitor","Network connectivity changed: UNAVAILABLE"),this.Wr))e(1)}static C(){return"undefined"!=typeof window&&void 0!==window.addEventListener&&void 0!==window.removeEventListener}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let ly={BatchGetDocuments:"batchGet",Commit:"commit",RunQuery:"runQuery",RunAggregationQuery:"runAggregationQuery"};/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class lv{constructor(e){this.Hr=e.Hr,this.Jr=e.Jr}Yr(e){this.Xr=e}Zr(e){this.eo=e}onMessage(e){this.no=e}close(){this.Jr()}send(e){this.Hr(e)}so(){this.Xr()}io(e){this.eo(e)}ro(e){this.no(e)}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class lw extends class{constructor(e){this.databaseInfo=e,this.databaseId=e.databaseId;let t=e.ssl?"https":"http";this.oo=t+"://"+e.host,this.uo="projects/"+this.databaseId.projectId+"/databases/"+this.databaseId.database+"/documents"}get co(){return!1}ao(e,t,n,r,i){let s=this.ho(e,t);nj("RestConnection","Sending: ",s,n);let a={};return this.lo(a,r,i),this.fo(e,s,a,n).then(e=>(nj("RestConnection","Received: ",e),e),t=>{throw nz("RestConnection",`${e} failed with error: `,t,"url: ",s,"request:",n),t})}_o(e,t,n,r,i,s){return this.ao(e,t,n,r,i)}lo(e,t,n){e["X-Goog-Api-Client"]="gl-js/ fire/"+nU,e["Content-Type"]="text/plain",this.databaseInfo.appId&&(e["X-Firebase-GMPID"]=this.databaseInfo.appId),t&&t.headers.forEach((t,n)=>e[n]=t),n&&n.headers.forEach((t,n)=>e[n]=t)}ho(e,t){let n=ly[e];return`${this.oo}/v1/${t}:${n}`}}{constructor(e){super(e),this.forceLongPolling=e.forceLongPolling,this.autoDetectLongPolling=e.autoDetectLongPolling,this.useFetchStreams=e.useFetchStreams}fo(e,t,n,r){return new Promise((i,s)=>{let a=new nP;a.setWithCredentials(!0),a.listenOnce(nx.COMPLETE,()=>{try{switch(a.getLastErrorCode()){case nC.NO_ERROR:let t=a.getResponseJson();nj("Connection","XHR received:",JSON.stringify(t)),i(t);break;case nC.TIMEOUT:nj("Connection",'RPC "'+e+'" timed out'),s(new nQ(nW.DEADLINE_EXCEEDED,"Request time out"));break;case nC.HTTP_ERROR:let n=a.getStatus();if(nj("Connection",'RPC "'+e+'" failed with status:',n,"response text:",a.getResponseText()),n>0){let r=a.getResponseJson();Array.isArray(r)&&(r=r[0]);let o=null==r?void 0:r.error;if(o&&o.status&&o.message){let l=function(e){let t=e.toLowerCase().replace(/_/g,"-");return Object.values(nW).indexOf(t)>=0?t:nW.UNKNOWN}(o.status);s(new nQ(l,o.message))}else s(new nQ(nW.UNKNOWN,"Server responded with status "+a.getStatus()))}else s(new nQ(nW.UNAVAILABLE,"Connection failed."));break;default:nK()}}finally{nj("Connection",'RPC "'+e+'" completed.')}});let o=JSON.stringify(r);a.send(t,"POST",o,n,15)})}wo(e,t,n){let r=[this.oo,"/","google.firestore.v1.Firestore","/",e,"/channel"],i=nk(),s=nA(),a={httpSessionIdParam:"gsessionid",initMessageHeaders:{},messageUrlParams:{database:`projects/${this.databaseId.projectId}/databases/${this.databaseId.database}`},sendRawJson:!0,supportsCrossDomainXhr:!0,internalChannelParams:{forwardChannelRequestTimeoutMs:6e5},forceLongPolling:this.forceLongPolling,detectBufferingProxy:this.autoDetectLongPolling};this.useFetchStreams&&(a.xmlHttpFactory=new nN({})),this.lo(a.initMessageHeaders,t,n),a.encodeInitMessageHeaders=!0;let o=r.join("");nj("Connection","Creating WebChannel: "+o,a);let u=i.createWebChannel(o,a),c=!1,h=!1,d=new lv({Hr:e=>{h?nj("Connection","Not sending because WebChannel is closed:",e):(c||(nj("Connection","Opening WebChannel transport."),u.open(),c=!0),nj("Connection","WebChannel sending:",e),u.send(e))},Jr:()=>u.close()}),f=(e,t,n)=>{e.listen(t,e=>{try{n(e)}catch(t){setTimeout(()=>{throw t},0)}})};return f(u,nO.EventType.OPEN,()=>{h||nj("Connection","WebChannel transport opened.")}),f(u,nO.EventType.CLOSE,()=>{h||(h=!0,nj("Connection","WebChannel transport closed"),d.io())}),f(u,nO.EventType.ERROR,e=>{h||(h=!0,nz("Connection","WebChannel transport errored:",e),d.io(new nQ(nW.UNAVAILABLE,"The operation could not be completed")))}),f(u,nO.EventType.MESSAGE,e=>{var t;if(!h){let n=e.data[0];n||nK();let r=n.error||(null===(t=n[0])||void 0===t?void 0:t.error);if(r){nj("Connection","WebChannel received error:",r);let i=r.status,s=function(e){let t=l[e];if(void 0!==t)return s_(t)}(i),a=r.message;void 0===s&&(s=nW.INTERNAL,a="Unknown error status: "+i+" with message "+r.message),h=!0,d.io(new nQ(s,a)),u.close()}else nj("Connection","WebChannel received:",n),d.ro(n)}}),f(s,nR.STAT_EVENT,e=>{e.stat===nD.PROXY?nj("Connection","Detected buffering proxy"):e.stat===nD.NOPROXY&&nj("Connection","Detected no buffering proxy")}),setTimeout(()=>{d.so()},0),d}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *//**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function l_(){return"undefined"!=typeof window?window:null}function lb(){return"undefined"!=typeof document?document:null}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function lI(e){return new s$(e,!0)}class lT{constructor(e,t,n=1e3,r=1.5,i=6e4){this.Hs=e,this.timerId=t,this.mo=n,this.yo=r,this.po=i,this.Io=0,this.To=null,this.Eo=Date.now(),this.reset()}reset(){this.Io=0}Ao(){this.Io=this.po}Ro(e){this.cancel();let t=Math.floor(this.Io+this.bo()),n=Math.max(0,Date.now()-this.Eo),r=Math.max(0,t-n);r>0&&nj("ExponentialBackoff",`Backing off for ${r} ms (base delay: ${this.Io} ms, delay with jitter: ${t} ms, last attempt: ${n} ms ago)`),this.To=this.Hs.enqueueAfterDelay(this.timerId,r,()=>(this.Eo=Date.now(),e())),this.Io*=this.yo,this.Io<this.mo&&(this.Io=this.mo),this.Io>this.po&&(this.Io=this.po)}Po(){null!==this.To&&(this.To.skipDelay(),this.To=null)}cancel(){null!==this.To&&(this.To.cancel(),this.To=null)}bo(){return(Math.random()-.5)*this.Io}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class lE{constructor(e,t,n,r,i,s,a,o){this.Hs=e,this.vo=n,this.Vo=r,this.connection=i,this.authCredentialsProvider=s,this.appCheckCredentialsProvider=a,this.listener=o,this.state=0,this.So=0,this.Do=null,this.Co=null,this.stream=null,this.xo=new lT(e,t)}No(){return 1===this.state||5===this.state||this.ko()}ko(){return 2===this.state||3===this.state}start(){4!==this.state?this.auth():this.Oo()}async stop(){this.No()&&await this.close(0)}Mo(){this.state=0,this.xo.reset()}Fo(){this.ko()&&null===this.Do&&(this.Do=this.Hs.enqueueAfterDelay(this.vo,6e4,()=>this.$o()))}Bo(e){this.Lo(),this.stream.send(e)}async $o(){if(this.ko())return this.close(0)}Lo(){this.Do&&(this.Do.cancel(),this.Do=null)}qo(){this.Co&&(this.Co.cancel(),this.Co=null)}async close(e,t){this.Lo(),this.qo(),this.xo.cancel(),this.So++,4!==e?this.xo.reset():t&&t.code===nW.RESOURCE_EXHAUSTED?(n$(t.toString()),n$("Using maximum backoff delay to prevent overloading the backend."),this.xo.Ao()):t&&t.code===nW.UNAUTHENTICATED&&3!==this.state&&(this.authCredentialsProvider.invalidateToken(),this.appCheckCredentialsProvider.invalidateToken()),null!==this.stream&&(this.Uo(),this.stream.close(),this.stream=null),this.state=e,await this.listener.Zr(t)}Uo(){}auth(){this.state=1;let e=this.Ko(this.So),t=this.So;Promise.all([this.authCredentialsProvider.getToken(),this.appCheckCredentialsProvider.getToken()]).then(([e,n])=>{this.So===t&&this.Go(e,n)},t=>{e(()=>{let e=new nQ(nW.UNKNOWN,"Fetching auth token failed: "+t.message);return this.Qo(e)})})}Go(e,t){let n=this.Ko(this.So);this.stream=this.jo(e,t),this.stream.Yr(()=>{n(()=>(this.state=2,this.Co=this.Hs.enqueueAfterDelay(this.Vo,1e4,()=>(this.ko()&&(this.state=3),Promise.resolve())),this.listener.Yr()))}),this.stream.Zr(e=>{n(()=>this.Qo(e))}),this.stream.onMessage(e=>{n(()=>this.onMessage(e))})}Oo(){this.state=5,this.xo.Ro(async()=>{this.state=0,this.start()})}Qo(e){return nj("PersistentStream",`close with error: ${e}`),this.stream=null,this.close(4,e)}Ko(e){return t=>{this.Hs.enqueueAndForget(()=>this.So===e?t():(nj("PersistentStream","stream callback skipped by getCloseGuardedDispatcher."),Promise.resolve()))}}}class lS extends lE{constructor(e,t,n,r,i,s){super(e,"listen_stream_connection_backoff","listen_stream_idle","health_check_timeout",t,n,r,s),this.yt=i}jo(e,t){return this.connection.wo("Listen",e,t)}onMessage(e){this.xo.reset();let t=function(e,t){let n;if("targetChange"in t){var r,i;t.targetChange;let s="NO_CHANGE"===(r=t.targetChange.targetChangeType||"NO_CHANGE")?0:"ADD"===r?1:"REMOVE"===r?2:"CURRENT"===r?3:"RESET"===r?4:nK(),a=t.targetChange.targetIds||[],o=(i=t.targetChange.resumeToken,e.wt?(void 0===i||"string"==typeof i||nK(),rV.fromBase64String(i||"")):(void 0===i||i instanceof Uint8Array||nK(),rV.fromUint8Array(i||new Uint8Array))),l=t.targetChange.cause,u=l&&function(e){let t=void 0===e.code?nW.UNKNOWN:s_(e.code);return new nQ(t,e.message||"")}(l);n=new sL(s,a,o,u||null)}else if("documentChange"in t){t.documentChange;let c=t.documentChange;c.document,c.document.name,c.document.updateTime;let h=sY(e,c.document.name),d=sK(c.document.updateTime),f=c.document.createTime?sK(c.document.createTime):n7.min(),p=new iC({mapValue:{fields:c.document.fields}}),m=ix.newFoundDocument(h,d,f,p),g=c.targetIds||[],y=c.removedTargetIds||[];n=new sO(g,y,m.key,m)}else if("documentDelete"in t){t.documentDelete;let v=t.documentDelete;v.document;let w=sY(e,v.document),_=v.readTime?sK(v.readTime):n7.min(),b=ix.newNoDocument(w,_),I=v.removedTargetIds||[];n=new sO([],I,b.key,b)}else if("documentRemove"in t){t.documentRemove;let T=t.documentRemove;T.document;let E=sY(e,T.document),S=T.removedTargetIds||[];n=new sO([],S,E,null)}else{if(!("filter"in t))return nK();{t.filter;let k=t.filter;k.targetId;let A=k.count||0,C=new sv(A),x=k.targetId;n=new sP(x,C)}}return n}(this.yt,e),n=function(e){if(!("targetChange"in e))return n7.min();let t=e.targetChange;return t.targetIds&&t.targetIds.length?n7.min():t.readTime?sK(t.readTime):n7.min()}(e);return this.listener.Wo(t,n)}zo(e){let t={};t.database=sZ(this.yt),t.addTarget=function(e,t){let n;let r=t.target;return(n=iP(r)?{documents:s6(e,r)}:{query:s5(e,r)}).targetId=t.targetId,t.resumeToken.approximateByteSize()>0?n.resumeToken=sG(e,t.resumeToken):t.snapshotVersion.compareTo(n7.min())>0&&(n.readTime=sz(e,t.snapshotVersion.toTimestamp())),n}(this.yt,e);let n=function(e,t){let n=function(e,t){switch(t){case 0:return null;case 1:return"existence-filter-mismatch";case 2:return"limbo-document";default:return nK()}}(0,t.purpose);return null==n?null:{"goog-listen-tags":n}}(this.yt,e);n&&(t.labels=n),this.Bo(t)}Ho(e){let t={};t.database=sZ(this.yt),t.removeTarget=e,this.Bo(t)}}class lk extends lE{constructor(e,t,n,r,i,s){super(e,"write_stream_connection_backoff","write_stream_idle","health_check_timeout",t,n,r,s),this.yt=i,this.Jo=!1}get Yo(){return this.Jo}start(){this.Jo=!1,this.lastStreamToken=void 0,super.start()}Uo(){this.Jo&&this.Xo([])}jo(e,t){return this.connection.wo("Write",e,t)}onMessage(e){var t,n;if(e.streamToken||nK(),this.lastStreamToken=e.streamToken,this.Jo){this.xo.reset();let r=(t=e.writeResults,n=e.commitTime,t&&t.length>0?(void 0!==n||nK(),t.map(e=>{let t;return(t=e.updateTime?sK(e.updateTime):sK(n)).isEqual(n7.min())&&(t=sK(n)),new si(t,e.transformResults||[])})):[]),i=sK(e.commitTime);return this.listener.Zo(i,r)}return e.writeResults&&0!==e.writeResults.length&&nK(),this.Jo=!0,this.listener.tu()}eu(){let e={};e.database=sZ(this.yt),this.Bo(e)}Xo(e){let t={streamToken:this.lastStreamToken,writes:e.map(e=>s4(this.yt,e))};this.Bo(t)}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class lA extends class{}{constructor(e,t,n,r){super(),this.authCredentials=e,this.appCheckCredentials=t,this.connection=n,this.yt=r,this.nu=!1}su(){if(this.nu)throw new nQ(nW.FAILED_PRECONDITION,"The client has already been terminated.")}ao(e,t,n){return this.su(),Promise.all([this.authCredentials.getToken(),this.appCheckCredentials.getToken()]).then(([r,i])=>this.connection.ao(e,t,n,r,i)).catch(e=>{throw"FirebaseError"===e.name?(e.code===nW.UNAUTHENTICATED&&(this.authCredentials.invalidateToken(),this.appCheckCredentials.invalidateToken()),e):new nQ(nW.UNKNOWN,e.toString())})}_o(e,t,n,r){return this.su(),Promise.all([this.authCredentials.getToken(),this.appCheckCredentials.getToken()]).then(([i,s])=>this.connection._o(e,t,n,i,s,r)).catch(e=>{throw"FirebaseError"===e.name?(e.code===nW.UNAUTHENTICATED&&(this.authCredentials.invalidateToken(),this.appCheckCredentials.invalidateToken()),e):new nQ(nW.UNKNOWN,e.toString())})}terminate(){this.nu=!0}}class lC{constructor(e,t){this.asyncQueue=e,this.onlineStateHandler=t,this.state="Unknown",this.iu=0,this.ru=null,this.ou=!0}uu(){0===this.iu&&(this.cu("Unknown"),this.ru=this.asyncQueue.enqueueAfterDelay("online_state_timeout",1e4,()=>(this.ru=null,this.au("Backend didn't respond within 10 seconds."),this.cu("Offline"),Promise.resolve())))}hu(e){"Online"===this.state?this.cu("Unknown"):(this.iu++,this.iu>=1&&(this.lu(),this.au(`Connection failed 1 times. Most recent error: ${e.toString()}`),this.cu("Offline")))}set(e){this.lu(),this.iu=0,"Online"===e&&(this.ou=!1),this.cu(e)}cu(e){e!==this.state&&(this.state=e,this.onlineStateHandler(e))}au(e){let t=`Could not reach Cloud Firestore backend. ${e}
This typically indicates that your device does not have a healthy Internet connection at the moment. The client will operate in offline mode until it is able to successfully connect to the backend.`;this.ou?(n$(t),this.ou=!1):nj("OnlineStateTracker",t)}lu(){null!==this.ru&&(this.ru.cancel(),this.ru=null)}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class lx{constructor(e,t,n,r,i){this.localStore=e,this.datastore=t,this.asyncQueue=n,this.remoteSyncer={},this.fu=[],this.du=new Map,this._u=new Set,this.wu=[],this.mu=i,this.mu.Ur(e=>{n.enqueueAndForget(async()=>{lU(this)&&(nj("RemoteStore","Restarting streams for network reachability change."),await async function(e){e._u.add(4),await lD(e),e.gu.set("Unknown"),e._u.delete(4),await lR(e)}(this))})}),this.gu=new lC(n,r)}}async function lR(e){if(lU(e))for(let t of e.wu)await t(!0)}async function lD(e){for(let t of e.wu)await t(!1)}function lN(e,t){e.du.has(t.targetId)||(e.du.set(t.targetId,t),lF(e)?lM(e):lZ(e).ko()&&lP(e,t))}function lO(e,t){let n=lZ(e);e.du.delete(t),n.ko()&&lL(e,t),0===e.du.size&&(n.ko()?n.Fo():lU(e)&&e.gu.set("Unknown"))}function lP(e,t){e.yu.Ot(t.targetId),lZ(e).zo(t)}function lL(e,t){e.yu.Ot(t),lZ(e).Ho(t)}function lM(e){e.yu=new sF({getRemoteKeysForTarget:t=>e.remoteSyncer.getRemoteKeysForTarget(t),ne:t=>e.du.get(t)||null}),lZ(e).start(),e.gu.uu()}function lF(e){return lU(e)&&!lZ(e).No()&&e.du.size>0}function lU(e){return 0===e._u.size}async function lV(e){e.du.forEach((t,n)=>{lP(e,t)})}async function lq(e,t){e.yu=void 0,lF(e)?(e.gu.hu(t),lM(e)):e.gu.set("Unknown")}async function lB(e,t,n){if(e.gu.set("Online"),t instanceof sL&&2===t.state&&t.cause)try{await async function(e,t){let n=t.cause;for(let r of t.targetIds)e.du.has(r)&&(await e.remoteSyncer.rejectListen(r,n),e.du.delete(r),e.yu.removeTarget(r))}(e,t)}catch(r){nj("RemoteStore","Failed to remove targets %s: %s ",t.targetIds.join(","),r),await lj(e,r)}else if(t instanceof sO?e.yu.Kt(t):t instanceof sP?e.yu.Jt(t):e.yu.jt(t),!n.isEqual(n7.min()))try{let i=await o6(e.localStore);n.compareTo(i)>=0&&await function(e,t){let n=e.yu.Zt(t);return n.targetChanges.forEach((n,r)=>{if(n.resumeToken.approximateByteSize()>0){let i=e.du.get(r);i&&e.du.set(r,i.withResumeToken(n.resumeToken,t))}}),n.targetMismatches.forEach(t=>{let n=e.du.get(t);if(!n)return;e.du.set(t,n.withResumeToken(rV.EMPTY_BYTE_STRING,n.snapshotVersion)),lL(e,t);let r=new aC(n.target,t,1,n.sequenceNumber);lP(e,r)}),e.remoteSyncer.applyRemoteEvent(n)}(e,n)}catch(s){nj("RemoteStore","Failed to raise snapshot:",s),await lj(e,s)}}async function lj(e,t,n){if(!rI(t))throw t;e._u.add(1),await lD(e),e.gu.set("Offline"),n||(n=()=>o6(e.localStore)),e.asyncQueue.enqueueRetryable(async()=>{nj("RemoteStore","Retrying IndexedDB access"),await n(),e._u.delete(1),await lR(e)})}function l$(e,t){return t().catch(n=>lj(e,n,t))}async function lz(e){let t=l0(e),n=e.fu.length>0?e.fu[e.fu.length-1].batchId:-1;for(;lU(e)&&e.fu.length<10;)try{let r=await function(e,t){return e.persistence.runTransaction("Get next mutation batch","readonly",n=>(void 0===t&&(t=-1),e.mutationQueue.getNextMutationBatchAfterBatchId(n,t)))}(e.localStore,n);if(null===r){0===e.fu.length&&t.Fo();break}n=r.batchId,function(e,t){e.fu.push(t);let n=l0(e);n.ko()&&n.Yo&&n.Xo(t.mutations)}(e,r)}catch(i){await lj(e,i)}lG(e)&&lK(e)}function lG(e){return lU(e)&&!l0(e).No()&&e.fu.length>0}function lK(e){l0(e).start()}async function lH(e){l0(e).eu()}async function lW(e){let t=l0(e);for(let n of e.fu)t.Xo(n.mutations)}async function lQ(e,t,n){let r=e.fu.shift(),i=ak.from(r,t,n);await l$(e,()=>e.remoteSyncer.applySuccessfulWrite(i)),await lz(e)}async function lY(e,t){t&&l0(e).Yo&&await async function(e,t){var n;if(sw(n=t.code)&&n!==nW.ABORTED){let r=e.fu.shift();l0(e).Mo(),await l$(e,()=>e.remoteSyncer.rejectFailedWrite(r.batchId,t)),await lz(e)}}(e,t),lG(e)&&lK(e)}async function lX(e,t){e.asyncQueue.verifyOperationInProgress(),nj("RemoteStore","RemoteStore received new credentials");let n=lU(e);e._u.add(3),await lD(e),n&&e.gu.set("Unknown"),await e.remoteSyncer.handleCredentialChange(t),e._u.delete(3),await lR(e)}async function lJ(e,t){t?(e._u.delete(2),await lR(e)):t||(e._u.add(2),await lD(e),e.gu.set("Unknown"))}function lZ(e){var t,n,r;return e.pu||(e.pu=(t=e.datastore,n=e.asyncQueue,r={Yr:lV.bind(null,e),Zr:lq.bind(null,e),Wo:lB.bind(null,e)},t.su(),new lS(n,t.connection,t.authCredentials,t.appCheckCredentials,t.yt,r)),e.wu.push(async t=>{t?(e.pu.Mo(),lF(e)?lM(e):e.gu.set("Unknown")):(await e.pu.stop(),e.yu=void 0)})),e.pu}function l0(e){var t,n,r;return e.Iu||(e.Iu=(t=e.datastore,n=e.asyncQueue,r={Yr:lH.bind(null,e),Zr:lY.bind(null,e),tu:lW.bind(null,e),Zo:lQ.bind(null,e)},t.su(),new lk(n,t.connection,t.authCredentials,t.appCheckCredentials,t.yt,r)),e.wu.push(async t=>{t?(e.Iu.Mo(),await lz(e)):(await e.Iu.stop(),e.fu.length>0&&(nj("RemoteStore",`Stopping write stream with ${e.fu.length} pending writes`),e.fu=[]))})),e.Iu}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class l1{constructor(e,t,n,r,i){this.asyncQueue=e,this.timerId=t,this.targetTimeMs=n,this.op=r,this.removalCallback=i,this.deferred=new nY,this.then=this.deferred.promise.then.bind(this.deferred.promise),this.deferred.promise.catch(e=>{})}static createAndSchedule(e,t,n,r,i){let s=Date.now()+n,a=new l1(e,t,s,r,i);return a.start(n),a}start(e){this.timerHandle=setTimeout(()=>this.handleDelayElapsed(),e)}skipDelay(){return this.handleDelayElapsed()}cancel(e){null!==this.timerHandle&&(this.clearTimeout(),this.deferred.reject(new nQ(nW.CANCELLED,"Operation cancelled"+(e?": "+e:""))))}handleDelayElapsed(){this.asyncQueue.enqueueAndForget(()=>null!==this.timerHandle?(this.clearTimeout(),this.op().then(e=>this.deferred.resolve(e))):Promise.resolve())}clearTimeout(){null!==this.timerHandle&&(this.removalCallback(this),clearTimeout(this.timerHandle),this.timerHandle=null)}}function l2(e,t){if(n$("AsyncQueue",`${t}: ${e}`),rI(e))return new nQ(nW.UNAVAILABLE,`${t}: ${e}`);throw e}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class l4{constructor(e){this.comparator=e?(t,n)=>e(t,n)||ri.comparator(t.key,n.key):(e,t)=>ri.comparator(e.key,t.key),this.keyedMap=sE(),this.sortedSet=new ib(this.comparator)}static emptySet(e){return new l4(e.comparator)}has(e){return null!=this.keyedMap.get(e)}get(e){return this.keyedMap.get(e)}first(){return this.sortedSet.minKey()}last(){return this.sortedSet.maxKey()}isEmpty(){return this.sortedSet.isEmpty()}indexOf(e){let t=this.keyedMap.get(e);return t?this.sortedSet.indexOf(t):-1}get size(){return this.sortedSet.size}forEach(e){this.sortedSet.inorderTraversal((t,n)=>(e(t),!1))}add(e){let t=this.delete(e.key);return t.copy(t.keyedMap.insert(e.key,e),t.sortedSet.insert(e,null))}delete(e){let t=this.get(e);return t?this.copy(this.keyedMap.remove(e),this.sortedSet.remove(t)):this}isEqual(e){if(!(e instanceof l4)||this.size!==e.size)return!1;let t=this.sortedSet.getIterator(),n=e.sortedSet.getIterator();for(;t.hasNext();){let r=t.getNext().key,i=n.getNext().key;if(!r.isEqual(i))return!1}return!0}toString(){let e=[];return this.forEach(t=>{e.push(t.toString())}),0===e.length?"DocumentSet ()":"DocumentSet (\n  "+e.join("  \n")+"\n)"}copy(e,t){let n=new l4;return n.comparator=this.comparator,n.keyedMap=e,n.sortedSet=t,n}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class l3{constructor(){this.Tu=new ib(ri.comparator)}track(e){let t=e.doc.key,n=this.Tu.get(t);n?0!==e.type&&3===n.type?this.Tu=this.Tu.insert(t,e):3===e.type&&1!==n.type?this.Tu=this.Tu.insert(t,{type:n.type,doc:e.doc}):2===e.type&&2===n.type?this.Tu=this.Tu.insert(t,{type:2,doc:e.doc}):2===e.type&&0===n.type?this.Tu=this.Tu.insert(t,{type:0,doc:e.doc}):1===e.type&&0===n.type?this.Tu=this.Tu.remove(t):1===e.type&&2===n.type?this.Tu=this.Tu.insert(t,{type:1,doc:n.doc}):0===e.type&&1===n.type?this.Tu=this.Tu.insert(t,{type:2,doc:e.doc}):nK():this.Tu=this.Tu.insert(t,e)}Eu(){let e=[];return this.Tu.inorderTraversal((t,n)=>{e.push(n)}),e}}class l6{constructor(e,t,n,r,i,s,a,o,l){this.query=e,this.docs=t,this.oldDocs=n,this.docChanges=r,this.mutatedKeys=i,this.fromCache=s,this.syncStateChanged=a,this.excludesMetadataChanges=o,this.hasCachedResults=l}static fromInitialDocuments(e,t,n,r,i){let s=[];return t.forEach(e=>{s.push({type:0,doc:e})}),new l6(e,t,l4.emptySet(t),s,n,r,!0,!1,i)}get hasPendingWrites(){return!this.mutatedKeys.isEmpty()}isEqual(e){if(!(this.fromCache===e.fromCache&&this.hasCachedResults===e.hasCachedResults&&this.syncStateChanged===e.syncStateChanged&&this.mutatedKeys.isEqual(e.mutatedKeys)&&iW(this.query,e.query)&&this.docs.isEqual(e.docs)&&this.oldDocs.isEqual(e.oldDocs)))return!1;let t=this.docChanges,n=e.docChanges;if(t.length!==n.length)return!1;for(let r=0;r<t.length;r++)if(t[r].type!==n[r].type||!t[r].doc.isEqual(n[r].doc))return!1;return!0}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class l5{constructor(){this.Au=void 0,this.listeners=[]}}class l9{constructor(){this.queries=new sb(e=>iQ(e),iW),this.onlineState="Unknown",this.Ru=new Set}}async function l8(e,t){let n=t.query,r=!1,i=e.queries.get(n);if(i||(r=!0,i=new l5),r)try{i.Au=await e.onListen(n)}catch(a){let s=l2(a,`Initialization of query '${iY(t.query)}' failed`);return void t.onError(s)}e.queries.set(n,i),i.listeners.push(t),t.bu(e.onlineState),i.Au&&t.Pu(i.Au)&&un(e)}async function l7(e,t){let n=t.query,r=!1,i=e.queries.get(n);if(i){let s=i.listeners.indexOf(t);s>=0&&(i.listeners.splice(s,1),r=0===i.listeners.length)}if(r)return e.queries.delete(n),e.onUnlisten(n)}function ue(e,t){let n=!1;for(let r of t){let i=r.query,s=e.queries.get(i);if(s){for(let a of s.listeners)a.Pu(r)&&(n=!0);s.Au=r}}n&&un(e)}function ut(e,t,n){let r=e.queries.get(t);if(r)for(let i of r.listeners)i.onError(n);e.queries.delete(t)}function un(e){e.Ru.forEach(e=>{e.next()})}class ur{constructor(e,t,n){this.query=e,this.vu=t,this.Vu=!1,this.Su=null,this.onlineState="Unknown",this.options=n||{}}Pu(e){if(!this.options.includeMetadataChanges){let t=[];for(let n of e.docChanges)3!==n.type&&t.push(n);e=new l6(e.query,e.docs,e.oldDocs,t,e.mutatedKeys,e.fromCache,e.syncStateChanged,!0,e.hasCachedResults)}let r=!1;return this.Vu?this.Du(e)&&(this.vu.next(e),r=!0):this.Cu(e,this.onlineState)&&(this.xu(e),r=!0),this.Su=e,r}onError(e){this.vu.error(e)}bu(e){this.onlineState=e;let t=!1;return this.Su&&!this.Vu&&this.Cu(this.Su,e)&&(this.xu(this.Su),t=!0),t}Cu(e,t){return!e.fromCache||(!this.options.Nu||!("Offline"!==t))&&(!e.docs.isEmpty()||e.hasCachedResults||"Offline"===t)}Du(e){if(e.docChanges.length>0)return!0;let t=this.Su&&this.Su.hasPendingWrites!==e.hasPendingWrites;return!(!e.syncStateChanged&&!t)&&!0===this.options.includeMetadataChanges}xu(e){e=l6.fromInitialDocuments(e.query,e.docs,e.mutatedKeys,e.fromCache,e.hasCachedResults),this.Vu=!0,this.vu.next(e)}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class ui{constructor(e,t){this.ku=e,this.byteLength=t}Ou(){return"metadata"in this.ku}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class us{constructor(e){this.yt=e}Ji(e){return sY(this.yt,e)}Yi(e){return e.metadata.exists?s2(this.yt,e.document,!1):ix.newNoDocument(this.Ji(e.metadata.name),this.Xi(e.metadata.readTime))}Xi(e){return sK(e)}}class ua{constructor(e,t,n){this.Mu=e,this.localStore=t,this.yt=n,this.queries=[],this.documents=[],this.collectionGroups=new Set,this.progress=uo(e)}Fu(e){this.progress.bytesLoaded+=e.byteLength;let t=this.progress.documentsLoaded;if(e.ku.namedQuery)this.queries.push(e.ku.namedQuery);else if(e.ku.documentMetadata){this.documents.push({metadata:e.ku.documentMetadata}),e.ku.documentMetadata.exists||++t;let n=rt.fromString(e.ku.documentMetadata.name);this.collectionGroups.add(n.get(n.length-2))}else e.ku.document&&(this.documents[this.documents.length-1].document=e.ku.document,++t);return t!==this.progress.documentsLoaded?(this.progress.documentsLoaded=t,Object.assign({},this.progress)):null}$u(e){let t=new Map,n=new us(this.yt);for(let r of e)if(r.metadata.queries){let i=n.Ji(r.metadata.name);for(let s of r.metadata.queries){let a=(t.get(s)||sx()).add(i);t.set(s,a)}}return t}async complete(){let e=await lr(this.localStore,new us(this.yt),this.documents,this.Mu.id),t=this.$u(this.documents);for(let n of this.queries)await li(this.localStore,n,t.get(n.name));return this.progress.taskState="Success",{progress:this.progress,Bu:this.collectionGroups,Lu:e}}}function uo(e){return{taskState:"Running",documentsLoaded:0,bytesLoaded:0,totalDocuments:e.totalDocuments,totalBytes:e.totalBytes}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class ul{constructor(e){this.key=e}}class uu{constructor(e){this.key=e}}class uc{constructor(e,t){this.query=e,this.qu=t,this.Uu=null,this.hasCachedResults=!1,this.current=!1,this.Ku=sx(),this.mutatedKeys=sx(),this.Gu=iZ(e),this.Qu=new l4(this.Gu)}get ju(){return this.qu}Wu(e,t){let n=t?t.zu:new l3,r=t?t.Qu:this.Qu,i=t?t.mutatedKeys:this.mutatedKeys,s=r,a=!1,o="F"===this.query.limitType&&r.size===this.query.limit?r.last():null,l="L"===this.query.limitType&&r.size===this.query.limit?r.first():null;if(e.inorderTraversal((e,t)=>{let u=r.get(e),c=iX(this.query,t)?t:null,h=!!u&&this.mutatedKeys.has(u.key),d=!!c&&(c.hasLocalMutations||this.mutatedKeys.has(c.key)&&c.hasCommittedMutations),f=!1;u&&c?u.data.isEqual(c.data)?h!==d&&(n.track({type:3,doc:c}),f=!0):this.Hu(u,c)||(n.track({type:2,doc:c}),f=!0,(o&&this.Gu(c,o)>0||l&&0>this.Gu(c,l))&&(a=!0)):!u&&c?(n.track({type:0,doc:c}),f=!0):u&&!c&&(n.track({type:1,doc:u}),f=!0,(o||l)&&(a=!0)),f&&(c?(s=s.add(c),i=d?i.add(e):i.delete(e)):(s=s.delete(e),i=i.delete(e)))}),null!==this.query.limit)for(;s.size>this.query.limit;){let u="F"===this.query.limitType?s.last():s.first();s=s.delete(u.key),i=i.delete(u.key),n.track({type:1,doc:u})}return{Qu:s,zu:n,$i:a,mutatedKeys:i}}Hu(e,t){return e.hasLocalMutations&&t.hasCommittedMutations&&!t.hasLocalMutations}applyChanges(e,t,n){let r=this.Qu;this.Qu=e.Qu,this.mutatedKeys=e.mutatedKeys;let i=e.zu.Eu();i.sort((e,t)=>(function(e,t){let n=e=>{switch(e){case 0:return 1;case 2:case 3:return 2;case 1:return 0;default:return nK()}};return n(e)-n(t)})(e.type,t.type)||this.Gu(e.doc,t.doc)),this.Ju(n);let s=t?this.Yu():[],a=0===this.Ku.size&&this.current?1:0,o=a!==this.Uu;return(this.Uu=a,0!==i.length||o)?{snapshot:new l6(this.query,e.Qu,r,i,e.mutatedKeys,0===a,o,!1,!!n&&n.resumeToken.approximateByteSize()>0),Xu:s}:{Xu:s}}bu(e){return this.current&&"Offline"===e?(this.current=!1,this.applyChanges({Qu:this.Qu,zu:new l3,mutatedKeys:this.mutatedKeys,$i:!1},!1)):{Xu:[]}}Zu(e){return!this.qu.has(e)&&!!this.Qu.has(e)&&!this.Qu.get(e).hasLocalMutations}Ju(e){e&&(e.addedDocuments.forEach(e=>this.qu=this.qu.add(e)),e.modifiedDocuments.forEach(e=>{}),e.removedDocuments.forEach(e=>this.qu=this.qu.delete(e)),this.current=e.current)}Yu(){if(!this.current)return[];let e=this.Ku;this.Ku=sx(),this.Qu.forEach(e=>{this.Zu(e.key)&&(this.Ku=this.Ku.add(e.key))});let t=[];return e.forEach(e=>{this.Ku.has(e)||t.push(new uu(e))}),this.Ku.forEach(n=>{e.has(n)||t.push(new ul(n))}),t}tc(e){this.qu=e.Hi,this.Ku=sx();let t=this.Wu(e.documents);return this.applyChanges(t,!0)}ec(){return l6.fromInitialDocuments(this.query,this.Qu,this.mutatedKeys,0===this.Uu,this.hasCachedResults)}}class uh{constructor(e,t,n){this.query=e,this.targetId=t,this.view=n}}class ud{constructor(e){this.key=e,this.nc=!1}}class uf{constructor(e,t,n,r,i,s){this.localStore=e,this.remoteStore=t,this.eventManager=n,this.sharedClientState=r,this.currentUser=i,this.maxConcurrentLimboResolutions=s,this.sc={},this.ic=new sb(e=>iQ(e),iW),this.rc=new Map,this.oc=new Set,this.uc=new ib(ri.comparator),this.cc=new Map,this.ac=new oV,this.hc={},this.lc=new Map,this.fc=og.vn(),this.onlineState="Unknown",this.dc=void 0}get isPrimaryClient(){return!0===this.dc}}async function up(e,t){let n,r;let i=uj(e),s=i.ic.get(t);if(s)n=s.targetId,i.sharedClientState.addLocalQueryTarget(n),r=s.view.ec();else{let a=await o9(i.localStore,iG(t));i.isPrimaryClient&&lN(i.remoteStore,a);let o=i.sharedClientState.addLocalQueryTarget(a.targetId);r=await um(i,t,n=a.targetId,"current"===o,a.resumeToken)}return r}async function um(e,t,n,r,i){e._c=(t,n,r)=>(async function(e,t,n,r){let i=t.view.Wu(n);i.$i&&(i=await o7(e.localStore,t.query,!1).then(({documents:e})=>t.view.Wu(e,i)));let s=r&&r.targetChanges.get(t.targetId),a=t.view.applyChanges(i,e.isPrimaryClient,s);return uC(e,t.targetId,a.Xu),a.snapshot})(e,t,n,r);let s=await o7(e.localStore,t,!0),a=new uc(t,s.Hi),o=a.Wu(s.documents),l=sN.createSynthesizedTargetChangeForCurrentChange(n,r&&"Offline"!==e.onlineState,i),u=a.applyChanges(o,e.isPrimaryClient,l);uC(e,n,u.Xu);let c=new uh(t,n,a);return e.ic.set(t,c),e.rc.has(n)?e.rc.get(n).push(t):e.rc.set(n,[t]),u.snapshot}async function ug(e,t){let n=e.ic.get(t),r=e.rc.get(n.targetId);if(r.length>1)return e.rc.set(n.targetId,r.filter(e=>!iW(e,t))),void e.ic.delete(t);e.isPrimaryClient?(e.sharedClientState.removeLocalQueryTarget(n.targetId),e.sharedClientState.isActiveQueryTarget(n.targetId)||await o8(e.localStore,n.targetId,!1).then(()=>{e.sharedClientState.clearQueryState(n.targetId),lO(e.remoteStore,n.targetId),uk(e,n.targetId)}).catch(rg)):(uk(e,n.targetId),await o8(e.localStore,n.targetId,!0))}async function uy(e,t,n){let r=u$(e);try{var i,s;let a;let o=await function(e,t){let n,r;let i=n8.now(),s=t.reduce((e,t)=>e.add(t.key),sx());return e.persistence.runTransaction("Locally write mutations","readwrite",a=>{let o=sI,l=sx();return e.Gi.getEntries(a,s).next(e=>{(o=e).forEach((e,t)=>{t.isValidDocument()||(l=l.add(e))})}).next(()=>e.localDocuments.getOverlayedDocuments(a,o)).next(r=>{n=r;let s=[];for(let o of t){let l=function(e,t){let n=null;for(let r of e.fieldTransforms){let i=t.data.field(r.field),s=i3(r.transform,i||null);null!=s&&(null===n&&(n=iC.empty()),n.set(r.field,s))}return n||null}(o,n.get(o.key).overlayedDocument);null!=l&&s.push(new sd(o.key,l,function e(t){let n=[];return rO(t.fields,(t,r)=>{let i=new rr([t]);if(r6(r)){let s=e(r.mapValue).fields;if(0===s.length)n.push(i);else for(let a of s)n.push(i.child(a))}else n.push(i)}),new iA(n)}(l.value.mapValue),ss.exists(!0)))}return e.mutationQueue.addMutationBatch(a,i,s,t)}).next(t=>{r=t;let i=t.applyToLocalDocumentSet(n,l);return e.documentOverlayCache.saveOverlays(a,t.batchId,i)})}).then(()=>({batchId:r.batchId,changes:sS(n)}))}(r.localStore,t);r.sharedClientState.addPendingMutation(o.batchId),i=r,s=o.batchId,(a=i.hc[i.currentUser.toKey()])||(a=new ib(n5)),a=a.insert(s,n),i.hc[i.currentUser.toKey()]=a,await uR(r,o.changes),await lz(r.remoteStore)}catch(u){let l=l2(u,"Failed to persist write");n.reject(l)}}async function uv(e,t){try{let n=await function(e,t){let n=e,r=t.snapshotVersion,i=n.qi;return n.persistence.runTransaction("Apply remote event","readwrite-primary",e=>{let s=n.Gi.newChangeBuffer({trackRemovals:!0});i=n.qi;let a=[];t.targetChanges.forEach((s,o)=>{var l;let u=i.get(o);if(!u)return;a.push(n.Cs.removeMatchingKeys(e,s.removedDocuments,o).next(()=>n.Cs.addMatchingKeys(e,s.addedDocuments,o)));let c=u.withSequenceNumber(e.currentSequenceNumber);t.targetMismatches.has(o)?c=c.withResumeToken(rV.EMPTY_BYTE_STRING,n7.min()).withLastLimboFreeSnapshotVersion(n7.min()):s.resumeToken.approximateByteSize()>0&&(c=c.withResumeToken(s.resumeToken,r)),i=i.insert(o,c),l=c,(0===u.resumeToken.approximateByteSize()||l.snapshotVersion.toMicroseconds()-u.snapshotVersion.toMicroseconds()>=3e8||s.addedDocuments.size+s.modifiedDocuments.size+s.removedDocuments.size>0)&&a.push(n.Cs.updateTargetData(e,c))});let o=sI,l=sx();if(t.documentUpdates.forEach(r=>{t.resolvedLimboDocuments.has(r)&&a.push(n.persistence.referenceDelegate.updateLimboDocument(e,r))}),a.push(o5(e,s,t.documentUpdates).next(e=>{o=e.Wi,l=e.zi})),!r.isEqual(n7.min())){let u=n.Cs.getLastRemoteSnapshotVersion(e).next(t=>n.Cs.setTargetsMetadata(e,e.currentSequenceNumber,r));a.push(u)}return ry.waitFor(a).next(()=>s.apply(e)).next(()=>n.localDocuments.getLocalViewOfDocuments(e,o,l)).next(()=>o)}).then(e=>(n.qi=i,e))}(e.localStore,t);t.targetChanges.forEach((t,n)=>{let r=e.cc.get(n);r&&(t.addedDocuments.size+t.modifiedDocuments.size+t.removedDocuments.size<=1||nK(),t.addedDocuments.size>0?r.nc=!0:t.modifiedDocuments.size>0?r.nc||nK():t.removedDocuments.size>0&&(r.nc||nK(),r.nc=!1))}),await uR(e,n,t)}catch(r){await rg(r)}}function uw(e,t,n){let r=e;if(r.isPrimaryClient&&0===n||!r.isPrimaryClient&&1===n){let i=[];r.ic.forEach((e,n)=>{let r=n.view.bu(t);r.snapshot&&i.push(r.snapshot)}),function(e,t){let n=e;n.onlineState=t;let r=!1;n.queries.forEach((e,n)=>{for(let i of n.listeners)i.bu(t)&&(r=!0)}),r&&un(n)}(r.eventManager,t),i.length&&r.sc.Wo(i),r.onlineState=t,r.isPrimaryClient&&r.sharedClientState.setOnlineState(t)}}async function u_(e,t,n){let r=e;r.sharedClientState.updateQueryState(t,"rejected",n);let i=r.cc.get(t),s=i&&i.key;if(s){let a=new ib(ri.comparator);a=a.insert(s,ix.newNoDocument(s,n7.min()));let o=sx().add(s),l=new sD(n7.min(),new Map,new iE(n5),a,o);await uv(r,l),r.uc=r.uc.remove(s),r.cc.delete(t),ux(r)}else await o8(r.localStore,t,!1).then(()=>uk(r,t,n)).catch(rg)}async function ub(e,t){var n;let r=t.batch.batchId;try{let i=await (n=e.localStore).persistence.runTransaction("Acknowledge batch","readwrite-primary",e=>{let r=t.batch.keys(),i=n.Gi.newChangeBuffer({trackRemovals:!0});return(function(e,t,n,r){let i=n.batch,s=i.keys(),a=ry.resolve();return s.forEach(e=>{a=a.next(()=>r.getEntry(t,e)).next(t=>{let s=n.docVersions.get(e);null!==s||nK(),0>t.version.compareTo(s)&&(i.applyToRemoteDocument(t,n),t.isValidDocument()&&(t.setReadTime(n.commitVersion),r.addEntry(t)))})}),a.next(()=>e.mutationQueue.removeMutationBatch(t,i))})(n,e,t,i).next(()=>i.apply(e)).next(()=>n.mutationQueue.performConsistencyCheck(e)).next(()=>n.documentOverlayCache.removeOverlaysForBatchId(e,r,t.batch.batchId)).next(()=>n.localDocuments.recalculateAndSaveOverlaysForDocumentKeys(e,function(e){let t=sx();for(let n=0;n<e.mutationResults.length;++n)e.mutationResults[n].transformResults.length>0&&(t=t.add(e.batch.mutations[n].key));return t}(t))).next(()=>n.localDocuments.getDocuments(e,r))});uS(e,r,null),uE(e,r),e.sharedClientState.updateMutationState(r,"acknowledged"),await uR(e,i)}catch(s){await rg(s)}}async function uI(e,t,n){var r;try{let i=await (r=e.localStore).persistence.runTransaction("Reject batch","readwrite-primary",e=>{let n;return r.mutationQueue.lookupMutationBatch(e,t).next(t=>(null!==t||nK(),n=t.keys(),r.mutationQueue.removeMutationBatch(e,t))).next(()=>r.mutationQueue.performConsistencyCheck(e)).next(()=>r.documentOverlayCache.removeOverlaysForBatchId(e,n,t)).next(()=>r.localDocuments.recalculateAndSaveOverlaysForDocumentKeys(e,n)).next(()=>r.localDocuments.getDocuments(e,n))});uS(e,t,n),uE(e,t),e.sharedClientState.updateMutationState(t,"rejected",n),await uR(e,i)}catch(s){await rg(s)}}async function uT(e,t){var n;lU(e.remoteStore)||nj("SyncEngine","The network is disabled. The task returned by 'awaitPendingWrites()' will not complete until the network is enabled.");try{let r=await (n=e.localStore).persistence.runTransaction("Get highest unacknowledged batch id","readonly",e=>n.mutationQueue.getHighestUnacknowledgedBatchId(e));if(-1===r)return void t.resolve();let i=e.lc.get(r)||[];i.push(t),e.lc.set(r,i)}catch(a){let s=l2(a,"Initialization of waitForPendingWrites() operation failed");t.reject(s)}}function uE(e,t){(e.lc.get(t)||[]).forEach(e=>{e.resolve()}),e.lc.delete(t)}function uS(e,t,n){let r=e,i=r.hc[r.currentUser.toKey()];if(i){let s=i.get(t);s&&(n?s.reject(n):s.resolve(),i=i.remove(t)),r.hc[r.currentUser.toKey()]=i}}function uk(e,t,n=null){for(let r of(e.sharedClientState.removeLocalQueryTarget(t),e.rc.get(t)))e.ic.delete(r),n&&e.sc.wc(r,n);e.rc.delete(t),e.isPrimaryClient&&e.ac.ls(t).forEach(t=>{e.ac.containsKey(t)||uA(e,t)})}function uA(e,t){e.oc.delete(t.path.canonicalString());let n=e.uc.get(t);null!==n&&(lO(e.remoteStore,n),e.uc=e.uc.remove(t),e.cc.delete(n),ux(e))}function uC(e,t,n){for(let r of n)r instanceof ul?(e.ac.addReference(r.key,t),function(e,t){let n=t.key,r=n.path.canonicalString();e.uc.get(n)||e.oc.has(r)||(nj("SyncEngine","New document in limbo: "+n),e.oc.add(r),ux(e))}(e,r)):r instanceof uu?(nj("SyncEngine","Document no longer in limbo: "+r.key),e.ac.removeReference(r.key,t),e.ac.containsKey(r.key)||uA(e,r.key)):nK()}function ux(e){for(;e.oc.size>0&&e.uc.size<e.maxConcurrentLimboResolutions;){let t=e.oc.values().next().value;e.oc.delete(t);let n=new ri(rt.fromString(t)),r=e.fc.next();e.cc.set(r,new ud(n)),e.uc=e.uc.insert(n,r),lN(e.remoteStore,new aC(iG(iV(n.path)),r,2,rx.at))}}async function uR(e,t,n){let r=[],i=[],s=[];e.ic.isEmpty()||(e.ic.forEach((a,o)=>{s.push(e._c(o,t,n).then(t=>{if((t||n)&&e.isPrimaryClient&&e.sharedClientState.updateQueryState(o.targetId,(null==t?void 0:t.fromCache)?"not-current":"current"),t){r.push(t);let s=o1.Ci(o.targetId,t);i.push(s)}}))}),await Promise.all(s),e.sc.Wo(r),await async function(e,t){let n=e;try{await n.persistence.runTransaction("notifyLocalViewChanges","readwrite",e=>ry.forEach(t,t=>ry.forEach(t.Si,r=>n.persistence.referenceDelegate.addReference(e,t.targetId,r)).next(()=>ry.forEach(t.Di,r=>n.persistence.referenceDelegate.removeReference(e,t.targetId,r)))))}catch(r){if(!rI(r))throw r;nj("LocalStore","Failed to update sequence numbers: "+r)}for(let i of t){let s=i.targetId;if(!i.fromCache){let a=n.qi.get(s),o=a.snapshotVersion,l=a.withLastLimboFreeSnapshotVersion(o);n.qi=n.qi.insert(s,l)}}}(e.localStore,i))}async function uD(e,t){let n=e;if(!n.currentUser.isEqual(t)){nj("SyncEngine","User change. New user:",t.toKey());let r=await o3(n.localStore,t);n.currentUser=t,n.lc.forEach(e=>{e.forEach(e=>{e.reject(new nQ(nW.CANCELLED,"'waitForPendingWrites' promise is rejected due to a user change."))})}),n.lc.clear(),n.sharedClientState.handleUserChange(t,r.removedBatchIds,r.addedBatchIds),await uR(n,r.ji)}}function uN(e,t){let n=e.cc.get(t);if(n&&n.nc)return sx().add(n.key);{let r=sx(),i=e.rc.get(t);if(!i)return r;for(let s of i){let a=e.ic.get(s);r=r.unionWith(a.view.ju)}return r}}async function uO(e,t){let n=await o7(e.localStore,t.query,!0),r=t.view.tc(n);return e.isPrimaryClient&&uC(e,t.targetId,r.Xu),r}async function uP(e,t){return lt(e.localStore,t).then(t=>uR(e,t))}async function uL(e,t,n,r){let i=await function(e,t){let n=e.mutationQueue;return e.persistence.runTransaction("Lookup mutation documents","readonly",r=>n.Tn(r,t).next(t=>t?e.localDocuments.getDocuments(r,t):ry.resolve(null)))}(e.localStore,t);null!==i?("pending"===n?await lz(e.remoteStore):"acknowledged"===n||"rejected"===n?(uS(e,t,r||null),uE(e,t),function(e,t){e.mutationQueue.An(t)}(e.localStore,t)):nK(),await uR(e,i)):nj("SyncEngine","Cannot apply mutation batch with id: "+t)}async function uM(e,t){let n=e;if(uj(n),u$(n),!0===t&&!0!==n.dc){let r=n.sharedClientState.getAllActiveQueryTargets(),i=await uF(n,r.toArray());for(let s of(n.dc=!0,await lJ(n.remoteStore,!0),i))lN(n.remoteStore,s)}else if(!1===t&&!1!==n.dc){let a=[],o=Promise.resolve();n.rc.forEach((e,t)=>{n.sharedClientState.isLocalQueryTarget(t)?a.push(t):o=o.then(()=>(uk(n,t),o8(n.localStore,t,!0))),lO(n.remoteStore,t)}),await o,await uF(n,a),function(e){let t=e;t.cc.forEach((e,n)=>{lO(t.remoteStore,n)}),t.ac.fs(),t.cc=new Map,t.uc=new ib(ri.comparator)}(n),n.dc=!1,await lJ(n.remoteStore,!1)}}async function uF(e,t,n){let r=[],i=[];for(let s of t){let a;let o=e.rc.get(s);if(o&&0!==o.length)for(let l of(a=await o9(e.localStore,iG(o[0])),o)){let u=e.ic.get(l),c=await uO(e,u);c.snapshot&&i.push(c.snapshot)}else{let h=await le(e.localStore,s);await um(e,uU(h),s,!1,(a=await o9(e.localStore,h)).resumeToken)}r.push(a)}return e.sc.Wo(i),r}function uU(e){var t,n,r,i,s,a,o;return t=e.path,n=e.collectionGroup,r=e.orderBy,i=e.filters,s=e.limit,a=e.startAt,o=e.endAt,new iU(t,n,r,i,s,"F",a,o)}function uV(e){return e.localStore.persistence.vi()}async function uq(e,t,n,r){if(e.dc)return void nj("SyncEngine","Ignoring unexpected query state notification.");let i=e.rc.get(t);if(i&&i.length>0)switch(n){case"current":case"not-current":{let s=await lt(e.localStore,iJ(i[0])),a=sD.createSynthesizedRemoteEventForCurrentChange(t,"current"===n,rV.EMPTY_BYTE_STRING);await uR(e,s,a);break}case"rejected":await o8(e.localStore,t,!0),uk(e,t,r);break;default:nK()}}async function uB(e,t,n){let r=uj(e);if(r.dc){for(let i of t){if(r.rc.has(i)){nj("SyncEngine","Adding an already active target "+i);continue}let s=await le(r.localStore,i),a=await o9(r.localStore,s);await um(r,uU(s),a.targetId,!1,a.resumeToken),lN(r.remoteStore,a)}for(let o of n)r.rc.has(o)&&await o8(r.localStore,o,!1).then(()=>{lO(r.remoteStore,o),uk(r,o)}).catch(rg)}}function uj(e){let t=e;return t.remoteStore.remoteSyncer.applyRemoteEvent=uv.bind(null,t),t.remoteStore.remoteSyncer.getRemoteKeysForTarget=uN.bind(null,t),t.remoteStore.remoteSyncer.rejectListen=u_.bind(null,t),t.sc.Wo=ue.bind(null,t.eventManager),t.sc.wc=ut.bind(null,t.eventManager),t}function u$(e){let t=e;return t.remoteStore.remoteSyncer.applySuccessfulWrite=ub.bind(null,t),t.remoteStore.remoteSyncer.rejectFailedWrite=uI.bind(null,t),t}class uz{constructor(){this.synchronizeTabs=!1}async initialize(e){this.yt=lI(e.databaseInfo.databaseId),this.sharedClientState=this.gc(e),this.persistence=this.yc(e),await this.persistence.start(),this.localStore=this.Ic(e),this.gcScheduler=this.Tc(e,this.localStore),this.indexBackfillerScheduler=this.Ec(e,this.localStore)}Tc(e,t){return null}Ec(e,t){return null}Ic(e){var t,n,r,i;return t=this.persistence,n=new o2,r=e.initialUser,i=this.yt,new o4(t,n,r,i)}yc(e){return new oG(oH.Bs,this.yt)}gc(e){return new lp}async terminate(){this.gcScheduler&&this.gcScheduler.stop(),await this.sharedClientState.shutdown(),await this.persistence.shutdown()}}class uG extends uz{constructor(e,t,n){super(),this.Ac=e,this.cacheSizeBytes=t,this.forceOwnership=n,this.synchronizeTabs=!1}async initialize(e){await super.initialize(e),await this.Ac.initialize(this,e),await u$(this.Ac.syncEngine),await lz(this.Ac.remoteStore),await this.persistence.li(()=>(this.gcScheduler&&!this.gcScheduler.started&&this.gcScheduler.start(),this.indexBackfillerScheduler&&!this.indexBackfillerScheduler.started&&this.indexBackfillerScheduler.start(),Promise.resolve()))}Ic(e){var t,n,r,i;return t=this.persistence,n=new o2,r=e.initialUser,i=this.yt,new o4(t,n,r,i)}Tc(e,t){let n=this.persistence.referenceDelegate.garbageCollector;return new oT(n,e.asyncQueue,t)}Ec(e,t){let n=new rC(t,this.persistence);return new rA(e.asyncQueue,n)}yc(e){let t=o0(e.databaseInfo.databaseId,e.databaseInfo.persistenceKey),n=void 0!==this.cacheSizeBytes?ol.withCacheSize(this.cacheSizeBytes):ol.DEFAULT;return new oX(this.synchronizeTabs,t,e.clientId,n,e.asyncQueue,l_(),lb(),this.yt,this.sharedClientState,!!this.forceOwnership)}gc(e){return new lp}}class uK extends uG{constructor(e,t){super(e,t,!1),this.Ac=e,this.cacheSizeBytes=t,this.synchronizeTabs=!0}async initialize(e){await super.initialize(e);let t=this.Ac.syncEngine;this.sharedClientState instanceof lf&&(this.sharedClientState.syncEngine={Fr:uL.bind(null,t),$r:uq.bind(null,t),Br:uB.bind(null,t),vi:uV.bind(null,t),Mr:uP.bind(null,t)},await this.sharedClientState.start()),await this.persistence.li(async e=>{await uM(this.Ac.syncEngine,e),this.gcScheduler&&(e&&!this.gcScheduler.started?this.gcScheduler.start():e||this.gcScheduler.stop()),this.indexBackfillerScheduler&&(e&&!this.indexBackfillerScheduler.started?this.indexBackfillerScheduler.start():e||this.indexBackfillerScheduler.stop())})}gc(e){let t=l_();if(!lf.C(t))throw new nQ(nW.UNIMPLEMENTED,"IndexedDB persistence is only available on platforms that support LocalStorage.");let n=o0(e.databaseInfo.databaseId,e.databaseInfo.persistenceKey);return new lf(t,e.asyncQueue,n,e.clientId,e.initialUser)}}class uH{async initialize(e,t){this.localStore||(this.localStore=e.localStore,this.sharedClientState=e.sharedClientState,this.datastore=this.createDatastore(t),this.remoteStore=this.createRemoteStore(t),this.eventManager=this.createEventManager(t),this.syncEngine=this.createSyncEngine(t,!e.synchronizeTabs),this.sharedClientState.onlineStateHandler=e=>uw(this.syncEngine,e,1),this.remoteStore.remoteSyncer.handleCredentialChange=uD.bind(null,this.syncEngine),await lJ(this.remoteStore,this.syncEngine.isPrimaryClient))}createEventManager(e){return new l9}createDatastore(e){var t,n,r;let i=lI(e.databaseInfo.databaseId),s=(t=e.databaseInfo,new lw(t));return n=e.authCredentials,r=e.appCheckCredentials,new lA(n,r,s,i)}createRemoteStore(e){var t,n,r,i,s;return t=this.localStore,n=this.datastore,r=e.asyncQueue,i=e=>uw(this.syncEngine,e,0),s=lg.C()?new lg:new lm,new lx(t,n,r,i,s)}createSyncEngine(e,t){return function(e,t,n,r,i,s,a){let o=new uf(e,t,n,r,i,s);return a&&(o.dc=!0),o}(this.localStore,this.remoteStore,this.eventManager,this.sharedClientState,e.initialUser,e.maxConcurrentLimboResolutions,t)}terminate(){return async function(e){nj("RemoteStore","RemoteStore shutting down."),e._u.add(5),await lD(e),e.mu.shutdown(),e.gu.set("Unknown")}(this.remoteStore)}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function uW(e,t,n){if(!n)throw new nQ(nW.INVALID_ARGUMENT,`Function ${e}() cannot be called with an empty ${t}.`)}function uQ(e,t,n,r){if(!0===t&&!0===r)throw new nQ(nW.INVALID_ARGUMENT,`${e} and ${n} cannot be used together.`)}function uY(e){if(!ri.isDocumentKey(e))throw new nQ(nW.INVALID_ARGUMENT,`Invalid document reference. Document references must have an even number of segments, but ${e} has ${e.length}.`)}function uX(e){if(ri.isDocumentKey(e))throw new nQ(nW.INVALID_ARGUMENT,`Invalid collection reference. Collection references must have an odd number of segments, but ${e} has ${e.length}.`)}function uJ(e){if(void 0===e)return"undefined";if(null===e)return"null";if("string"==typeof e)return e.length>20&&(e=`${e.substring(0,20)}...`),JSON.stringify(e);if("number"==typeof e||"boolean"==typeof e)return""+e;if("object"==typeof e){if(e instanceof Array)return"an array";{var t;let n=(t=e).constructor?t.constructor.name:null;return n?`a custom ${n} object`:"an object"}}return"function"==typeof e?"a function":nK()}function uZ(e,t){if("_delegate"in e&&(e=e._delegate),!(e instanceof t)){if(t.name===e.constructor.name)throw new nQ(nW.INVALID_ARGUMENT,"Type does not match the expected instance. Did you pass a reference from a different Firestore SDK?");{let n=uJ(e);throw new nQ(nW.INVALID_ARGUMENT,`Expected type '${t.name}', but it was: ${n}`)}}return e}function u0(e,t){if(t<=0)throw new nQ(nW.INVALID_ARGUMENT,`Function ${e}() requires a positive number, but it was: ${t}.`)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let u1=new Map;class u2{constructor(e){var t;if(void 0===e.host){if(void 0!==e.ssl)throw new nQ(nW.INVALID_ARGUMENT,"Can't provide ssl option if host option is not set");this.host="firestore.googleapis.com",this.ssl=!0}else this.host=e.host,this.ssl=null===(t=e.ssl)||void 0===t||t;if(this.credentials=e.credentials,this.ignoreUndefinedProperties=!!e.ignoreUndefinedProperties,void 0===e.cacheSizeBytes)this.cacheSizeBytes=41943040;else{if(-1!==e.cacheSizeBytes&&e.cacheSizeBytes<1048576)throw new nQ(nW.INVALID_ARGUMENT,"cacheSizeBytes must be at least 1048576");this.cacheSizeBytes=e.cacheSizeBytes}this.experimentalForceLongPolling=!!e.experimentalForceLongPolling,this.experimentalAutoDetectLongPolling=!!e.experimentalAutoDetectLongPolling,this.useFetchStreams=!!e.useFetchStreams,uQ("experimentalForceLongPolling",e.experimentalForceLongPolling,"experimentalAutoDetectLongPolling",e.experimentalAutoDetectLongPolling)}isEqual(e){return this.host===e.host&&this.ssl===e.ssl&&this.credentials===e.credentials&&this.cacheSizeBytes===e.cacheSizeBytes&&this.experimentalForceLongPolling===e.experimentalForceLongPolling&&this.experimentalAutoDetectLongPolling===e.experimentalAutoDetectLongPolling&&this.ignoreUndefinedProperties===e.ignoreUndefinedProperties&&this.useFetchStreams===e.useFetchStreams}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class u4{constructor(e,t,n,r){this._authCredentials=e,this._appCheckCredentials=t,this._databaseId=n,this._app=r,this.type="firestore-lite",this._persistenceKey="(lite)",this._settings=new u2({}),this._settingsFrozen=!1}get app(){if(!this._app)throw new nQ(nW.FAILED_PRECONDITION,"Firestore was not initialized using the Firebase SDK. 'app' is not available");return this._app}get _initialized(){return this._settingsFrozen}get _terminated(){return void 0!==this._terminateTask}_setSettings(e){if(this._settingsFrozen)throw new nQ(nW.FAILED_PRECONDITION,"Firestore has already been started and its settings can no longer be changed. You can only modify settings before calling any other methods on a Firestore object.");this._settings=new u2(e),void 0!==e.credentials&&(this._authCredentials=function(e){if(!e)return new nJ;switch(e.type){case"gapi":let t=e.client;return new n2(t,e.sessionIndex||"0",e.iamToken||null,e.authTokenFactory||null);case"provider":return e.client;default:throw new nQ(nW.INVALID_ARGUMENT,"makeAuthCredentialsProvider failed due to invalid credential type")}}(e.credentials))}_getSettings(){return this._settings}_freezeSettings(){return this._settingsFrozen=!0,this._settings}_delete(){return this._terminateTask||(this._terminateTask=this._terminate()),this._terminateTask}toJSON(){return{app:this._app,databaseId:this._databaseId,settings:this._settings}}_terminate(){return function(e){let t=u1.get(e);t&&(nj("ComponentProvider","Removing Datastore"),u1.delete(e),t.terminate())}(this),Promise.resolve()}}function u3(e,t,n,r={}){var i;let s=(e=uZ(e,u4))._getSettings();if("firestore.googleapis.com"!==s.host&&s.host!==t&&nz("Host has been set in both settings() and useEmulator(), emulator host will be used"),e._setSettings(Object.assign(Object.assign({},s),{host:`${t}:${n}`,ssl:!1})),r.mockUserToken){let a,o;if("string"==typeof r.mockUserToken)a=r.mockUserToken,o=nF.MOCK_USER;else{a=(0,p.Sg)(r.mockUserToken,null===(i=e._app)||void 0===i?void 0:i.options.projectId);let l=r.mockUserToken.sub||r.mockUserToken.user_id;if(!l)throw new nQ(nW.INVALID_ARGUMENT,"mockUserToken must contain 'sub' or 'user_id' field!");o=new nF(l)}e._authCredentials=new nZ(new nX(a,o))}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class u6{constructor(e,t,n){this.converter=t,this._key=n,this.type="document",this.firestore=e}get _path(){return this._key.path}get id(){return this._key.path.lastSegment()}get path(){return this._key.path.canonicalString()}get parent(){return new u9(this.firestore,this.converter,this._key.path.popLast())}withConverter(e){return new u6(this.firestore,e,this._key)}}class u5{constructor(e,t,n){this.converter=t,this._query=n,this.type="query",this.firestore=e}withConverter(e){return new u5(this.firestore,e,this._query)}}class u9 extends u5{constructor(e,t,n){super(e,t,iV(n)),this._path=n,this.type="collection"}get id(){return this._query.path.lastSegment()}get path(){return this._query.path.canonicalString()}get parent(){let e=this._path.popLast();return e.isEmpty()?null:new u6(this.firestore,null,new ri(e))}withConverter(e){return new u9(this.firestore,e,this._path)}}function u8(e,t,...n){if(e=(0,p.m9)(e),uW("collection","path",t),e instanceof u4){let r=rt.fromString(t,...n);return uX(r),new u9(e,null,r)}{if(!(e instanceof u6||e instanceof u9))throw new nQ(nW.INVALID_ARGUMENT,"Expected first argument to collection() to be a CollectionReference, a DocumentReference or FirebaseFirestore");let i=e._path.child(rt.fromString(t,...n));return uX(i),new u9(e.firestore,null,i)}}function u7(e,t){if(e=uZ(e,u4),uW("collectionGroup","collection id",t),t.indexOf("/")>=0)throw new nQ(nW.INVALID_ARGUMENT,`Invalid collection ID '${t}' passed to function collectionGroup(). Collection IDs must not contain '/'.`);return new u5(e,null,new iU(rt.emptyPath(),t))}function ce(e,t,...n){if(e=(0,p.m9)(e),1==arguments.length&&(t=n6.R()),uW("doc","path",t),e instanceof u4){let r=rt.fromString(t,...n);return uY(r),new u6(e,null,new ri(r))}{if(!(e instanceof u6||e instanceof u9))throw new nQ(nW.INVALID_ARGUMENT,"Expected first argument to collection() to be a CollectionReference, a DocumentReference or FirebaseFirestore");let i=e._path.child(rt.fromString(t,...n));return uY(i),new u6(e.firestore,e instanceof u9?e.converter:null,new ri(i))}}function ct(e,t){return e=(0,p.m9)(e),t=(0,p.m9)(t),(e instanceof u6||e instanceof u9)&&(t instanceof u6||t instanceof u9)&&e.firestore===t.firestore&&e.path===t.path&&e.converter===t.converter}function cn(e,t){return e=(0,p.m9)(e),t=(0,p.m9)(t),e instanceof u5&&t instanceof u5&&e.firestore===t.firestore&&iW(e._query,t._query)&&e.converter===t.converter}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function cr(e,t=10240){let n=0;return{async read(){if(n<e.byteLength){let r={value:e.slice(n,n+t),done:!1};return n+=t,r}return{done:!0}},async cancel(){},releaseLock(){},closed:Promise.reject("unimplemented")}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *//**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class ci{constructor(e){this.observer=e,this.muted=!1}next(e){this.observer.next&&this.Rc(this.observer.next,e)}error(e){this.observer.error?this.Rc(this.observer.error,e):n$("Uncaught Error in snapshot listener:",e.toString())}bc(){this.muted=!0}Rc(e,t){this.muted||setTimeout(()=>{this.muted||e(t)},0)}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class cs{constructor(e,t){this.Pc=e,this.yt=t,this.metadata=new nY,this.buffer=new Uint8Array,this.vc=new TextDecoder("utf-8"),this.Vc().then(e=>{e&&e.Ou()?this.metadata.resolve(e.ku.metadata):this.metadata.reject(Error(`The first element of the bundle is not a metadata, it is
             ${JSON.stringify(null==e?void 0:e.ku)}`))},e=>this.metadata.reject(e))}close(){return this.Pc.cancel()}async getMetadata(){return this.metadata.promise}async mc(){return await this.getMetadata(),this.Vc()}async Vc(){let e=await this.Sc();if(null===e)return null;let t=this.vc.decode(e),n=Number(t);isNaN(n)&&this.Dc(`length string (${t}) is not valid number`);let r=await this.Cc(n);return new ui(JSON.parse(r),e.length+n)}xc(){return this.buffer.findIndex(e=>123===e)}async Sc(){for(;0>this.xc()&&!await this.Nc(););if(0===this.buffer.length)return null;let e=this.xc();e<0&&this.Dc("Reached the end of bundle when a length string is expected.");let t=this.buffer.slice(0,e);return this.buffer=this.buffer.slice(e),t}async Cc(e){for(;this.buffer.length<e;)await this.Nc()&&this.Dc("Reached the end of bundle when more is expected.");let t=this.vc.decode(this.buffer.slice(0,e));return this.buffer=this.buffer.slice(e),t}Dc(e){throw this.Pc.cancel(),Error(`Invalid bundle format: ${e}`)}async Nc(){let e=await this.Pc.read();if(!e.done){let t=new Uint8Array(this.buffer.length+e.value.length);t.set(this.buffer),t.set(e.value,this.buffer.length),this.buffer=t}return e.done}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class ca{constructor(e){this.datastore=e,this.readVersions=new Map,this.mutations=[],this.committed=!1,this.lastWriteError=null,this.writtenDocs=new Set}async lookup(e){if(this.ensureCommitNotCalled(),this.mutations.length>0)throw new nQ(nW.INVALID_ARGUMENT,"Firestore transactions require all reads to be executed before all writes.");let t=await async function(e,t){let n=sZ(e.yt)+"/documents",r={documents:t.map(t=>sQ(e.yt,t))},i=await e._o("BatchGetDocuments",n,r,t.length),s=new Map;i.forEach(t=>{var n;let r=(n=e.yt,"found"in t?function(e,t){t.found||nK(),t.found.name,t.found.updateTime;let n=sY(e,t.found.name),r=sK(t.found.updateTime),i=t.found.createTime?sK(t.found.createTime):n7.min(),s=new iC({mapValue:{fields:t.found.fields}});return ix.newFoundDocument(n,r,i,s)}(n,t):"missing"in t?function(e,t){t.missing||nK(),t.readTime||nK();let n=sY(e,t.missing),r=sK(t.readTime);return ix.newNoDocument(n,r)}(n,t):nK());s.set(r.key.toString(),r)});let a=[];return t.forEach(e=>{let t=s.get(e.toString());t||nK(),a.push(t)}),a}(this.datastore,e);return t.forEach(e=>this.recordVersion(e)),t}set(e,t){this.write(t.toMutation(e,this.precondition(e))),this.writtenDocs.add(e.toString())}update(e,t){try{this.write(t.toMutation(e,this.preconditionForUpdate(e)))}catch(n){this.lastWriteError=n}this.writtenDocs.add(e.toString())}delete(e){this.write(new sg(e,this.precondition(e))),this.writtenDocs.add(e.toString())}async commit(){if(this.ensureCommitNotCalled(),this.lastWriteError)throw this.lastWriteError;let e=this.readVersions;this.mutations.forEach(t=>{e.delete(t.key.toString())}),e.forEach((e,t)=>{let n=ri.fromPath(t);this.mutations.push(new sy(n,this.precondition(n)))}),await async function(e,t){let n=sZ(e.yt)+"/documents",r={writes:t.map(t=>s4(e.yt,t))};await e.ao("Commit",n,r)}(this.datastore,this.mutations),this.committed=!0}recordVersion(e){let t;if(e.isFoundDocument())t=e.version;else{if(!e.isNoDocument())throw nK();t=n7.min()}let n=this.readVersions.get(e.key.toString());if(n){if(!t.isEqual(n))throw new nQ(nW.ABORTED,"Document version changed between two reads.")}else this.readVersions.set(e.key.toString(),t)}precondition(e){let t=this.readVersions.get(e.toString());return!this.writtenDocs.has(e.toString())&&t?t.isEqual(n7.min())?ss.exists(!1):ss.updateTime(t):ss.none()}preconditionForUpdate(e){let t=this.readVersions.get(e.toString());if(!this.writtenDocs.has(e.toString())&&t){if(t.isEqual(n7.min()))throw new nQ(nW.INVALID_ARGUMENT,"Can't update a document that doesn't exist.");return ss.updateTime(t)}return ss.exists(!0)}write(e){this.ensureCommitNotCalled(),this.mutations.push(e)}ensureCommitNotCalled(){}}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class co{constructor(e,t,n,r,i){this.asyncQueue=e,this.datastore=t,this.options=n,this.updateFunction=r,this.deferred=i,this.kc=n.maxAttempts,this.xo=new lT(this.asyncQueue,"transaction_retry")}run(){this.kc-=1,this.Oc()}Oc(){this.xo.Ro(async()=>{let e=new ca(this.datastore),t=this.Mc(e);t&&t.then(t=>{this.asyncQueue.enqueueAndForget(()=>e.commit().then(()=>{this.deferred.resolve(t)}).catch(e=>{this.Fc(e)}))}).catch(e=>{this.Fc(e)})})}Mc(e){try{let t=this.updateFunction(e);return!rL(t)&&t.catch&&t.then?t:(this.deferred.reject(Error("Transaction callback must return a Promise")),null)}catch(n){return this.deferred.reject(n),null}}Fc(e){this.kc>0&&this.$c(e)?(this.kc-=1,this.asyncQueue.enqueueAndForget(()=>(this.Oc(),Promise.resolve()))):this.deferred.reject(e)}$c(e){if("FirebaseError"===e.name){let t=e.code;return"aborted"===t||"failed-precondition"===t||"already-exists"===t||!sw(t)}return!1}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class cl{constructor(e,t,n,r){this.authCredentials=e,this.appCheckCredentials=t,this.asyncQueue=n,this.databaseInfo=r,this.user=nF.UNAUTHENTICATED,this.clientId=n6.R(),this.authCredentialListener=()=>Promise.resolve(),this.appCheckCredentialListener=()=>Promise.resolve(),this.authCredentials.start(n,async e=>{nj("FirestoreClient","Received user=",e.uid),await this.authCredentialListener(e),this.user=e}),this.appCheckCredentials.start(n,e=>(nj("FirestoreClient","Received new app check token=",e),this.appCheckCredentialListener(e,this.user)))}async getConfiguration(){return{asyncQueue:this.asyncQueue,databaseInfo:this.databaseInfo,clientId:this.clientId,authCredentials:this.authCredentials,appCheckCredentials:this.appCheckCredentials,initialUser:this.user,maxConcurrentLimboResolutions:100}}setCredentialChangeListener(e){this.authCredentialListener=e}setAppCheckTokenChangeListener(e){this.appCheckCredentialListener=e}verifyNotTerminated(){if(this.asyncQueue.isShuttingDown)throw new nQ(nW.FAILED_PRECONDITION,"The client has already been terminated.")}terminate(){this.asyncQueue.enterRestrictedMode();let e=new nY;return this.asyncQueue.enqueueAndForgetEvenWhileRestricted(async()=>{try{this.onlineComponents&&await this.onlineComponents.terminate(),this.offlineComponents&&await this.offlineComponents.terminate(),this.authCredentials.shutdown(),this.appCheckCredentials.shutdown(),e.resolve()}catch(n){let t=l2(n,"Failed to shutdown persistence");e.reject(t)}}),e.promise}}async function cu(e,t){e.asyncQueue.verifyOperationInProgress(),nj("FirestoreClient","Initializing OfflineComponentProvider");let n=await e.getConfiguration();await t.initialize(n);let r=n.initialUser;e.setCredentialChangeListener(async e=>{r.isEqual(e)||(await o3(t.localStore,e),r=e)}),t.persistence.setDatabaseDeletedListener(()=>e.terminate()),e.offlineComponents=t}async function cc(e,t){e.asyncQueue.verifyOperationInProgress();let n=await ch(e);nj("FirestoreClient","Initializing OnlineComponentProvider");let r=await e.getConfiguration();await t.initialize(n,r),e.setCredentialChangeListener(e=>lX(t.remoteStore,e)),e.setAppCheckTokenChangeListener((e,n)=>lX(t.remoteStore,n)),e.onlineComponents=t}async function ch(e){return e.offlineComponents||(nj("FirestoreClient","Using default OfflineComponentProvider"),await cu(e,new uz)),e.offlineComponents}async function cd(e){return e.onlineComponents||(nj("FirestoreClient","Using default OnlineComponentProvider"),await cc(e,new uH)),e.onlineComponents}function cf(e){return ch(e).then(e=>e.persistence)}function cp(e){return ch(e).then(e=>e.localStore)}function cm(e){return cd(e).then(e=>e.remoteStore)}function cg(e){return cd(e).then(e=>e.syncEngine)}async function cy(e){let t=await cd(e),n=t.eventManager;return n.onListen=up.bind(null,t.syncEngine),n.onUnlisten=ug.bind(null,t.syncEngine),n}function cv(e,t,n={}){let r=new nY;return e.asyncQueue.enqueueAndForget(async()=>(function(e,t,n,r,i){let s=new ci({next:s=>{t.enqueueAndForget(()=>l7(e,a));let o=s.docs.has(n);!o&&s.fromCache?i.reject(new nQ(nW.UNAVAILABLE,"Failed to get document because the client is offline.")):o&&s.fromCache&&r&&"server"===r.source?i.reject(new nQ(nW.UNAVAILABLE,'Failed to get document from server. (However, this document does exist in the local cache. Run again without setting source to "server" to retrieve the cached document.)')):i.resolve(s)},error:e=>i.reject(e)}),a=new ur(iV(n.path),s,{includeMetadataChanges:!0,Nu:!0});return l8(e,a)})(await cy(e),e.asyncQueue,t,n,r)),r.promise}function cw(e,t,n={}){let r=new nY;return e.asyncQueue.enqueueAndForget(async()=>(function(e,t,n,r,i){let s=new ci({next:n=>{t.enqueueAndForget(()=>l7(e,a)),n.fromCache&&"server"===r.source?i.reject(new nQ(nW.UNAVAILABLE,'Failed to get documents from server. (However, these documents may exist in the local cache. Run again without setting source to "server" to retrieve the cached documents.)')):i.resolve(n)},error:e=>i.reject(e)}),a=new ur(n,s,{includeMetadataChanges:!0,Nu:!0});return l8(e,a)})(await cy(e),e.asyncQueue,t,n,r)),r.promise}class c_{constructor(){this.Bc=Promise.resolve(),this.Lc=[],this.qc=!1,this.Uc=[],this.Kc=null,this.Gc=!1,this.Qc=!1,this.jc=[],this.xo=new lT(this,"async_queue_retry"),this.Wc=()=>{let e=lb();e&&nj("AsyncQueue","Visibility state changed to "+e.visibilityState),this.xo.Po()};let e=lb();e&&"function"==typeof e.addEventListener&&e.addEventListener("visibilitychange",this.Wc)}get isShuttingDown(){return this.qc}enqueueAndForget(e){this.enqueue(e)}enqueueAndForgetEvenWhileRestricted(e){this.zc(),this.Hc(e)}enterRestrictedMode(e){if(!this.qc){this.qc=!0,this.Qc=e||!1;let t=lb();t&&"function"==typeof t.removeEventListener&&t.removeEventListener("visibilitychange",this.Wc)}}enqueue(e){if(this.zc(),this.qc)return new Promise(()=>{});let t=new nY;return this.Hc(()=>this.qc&&this.Qc?Promise.resolve():(e().then(t.resolve,t.reject),t.promise)).then(()=>t.promise)}enqueueRetryable(e){this.enqueueAndForget(()=>(this.Lc.push(e),this.Jc()))}async Jc(){if(0!==this.Lc.length){try{await this.Lc[0](),this.Lc.shift(),this.xo.reset()}catch(e){if(!rI(e))throw e;nj("AsyncQueue","Operation failed with retryable error: "+e)}this.Lc.length>0&&this.xo.Ro(()=>this.Jc())}}Hc(e){let t=this.Bc.then(()=>(this.Gc=!0,e().catch(e=>{let t;this.Kc=e,this.Gc=!1;let n=(t=e.message||"",e.stack&&(t=e.stack.includes(e.message)?e.stack:e.message+"\n"+e.stack),t);throw n$("INTERNAL UNHANDLED ERROR: ",n),e}).then(e=>(this.Gc=!1,e))));return this.Bc=t,t}enqueueAfterDelay(e,t,n){this.zc(),this.jc.indexOf(e)>-1&&(t=0);let r=l1.createAndSchedule(this,e,t,n,e=>this.Yc(e));return this.Uc.push(r),r}zc(){this.Kc&&nK()}verifyOperationInProgress(){}async Xc(){let e;do await (e=this.Bc);while(e!==this.Bc)}Zc(e){for(let t of this.Uc)if(t.timerId===e)return!0;return!1}ta(e){return this.Xc().then(()=>{for(let t of(this.Uc.sort((e,t)=>e.targetTimeMs-t.targetTimeMs),this.Uc))if(t.skipDelay(),"all"!==e&&t.timerId===e)break;return this.Xc()})}ea(e){this.jc.push(e)}Yc(e){let t=this.Uc.indexOf(e);this.Uc.splice(t,1)}}function cb(e){return function(e,t){if("object"!=typeof e||null===e)return!1;for(let n of t)if(n in e&&"function"==typeof e[n])return!0;return!1}(e,["next","error","complete"])}class cI{constructor(){this._progressObserver={},this._taskCompletionResolver=new nY,this._lastProgress={taskState:"Running",totalBytes:0,totalDocuments:0,bytesLoaded:0,documentsLoaded:0}}onProgress(e,t,n){this._progressObserver={next:e,error:t,complete:n}}catch(e){return this._taskCompletionResolver.promise.catch(e)}then(e,t){return this._taskCompletionResolver.promise.then(e,t)}_completeWith(e){this._updateProgress(e),this._progressObserver.complete&&this._progressObserver.complete(),this._taskCompletionResolver.resolve(e)}_failWith(e){this._lastProgress.taskState="Error",this._progressObserver.next&&this._progressObserver.next(this._lastProgress),this._progressObserver.error&&this._progressObserver.error(e),this._taskCompletionResolver.reject(e)}_updateProgress(e){this._lastProgress=e,this._progressObserver.next&&this._progressObserver.next(e)}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let cT=-1;class cE extends u4{constructor(e,t,n,r){super(e,t,n,r),this.type="firestore",this._queue=new c_,this._persistenceKey=(null==r?void 0:r.name)||"[DEFAULT]"}_terminate(){return this._firestoreClient||ck(this),this._firestoreClient.terminate()}}function cS(e){return e._firestoreClient||ck(e),e._firestoreClient.verifyNotTerminated(),e._firestoreClient}function ck(e){var t,n,r,i;let s=e._freezeSettings(),a=(n=e._databaseId,r=(null===(t=e._app)||void 0===t?void 0:t.options.appId)||"",i=e._persistenceKey,new rR(n,r,i,s.host,s.ssl,s.experimentalForceLongPolling,s.experimentalAutoDetectLongPolling,s.useFetchStreams));e._firestoreClient=new cl(e._authCredentials,e._appCheckCredentials,e._queue,a)}function cA(e,t){cM(e=uZ(e,cE));let n=cS(e),r=e._freezeSettings(),i=new uH;return cx(n,i,new uG(i,r.cacheSizeBytes,null==t?void 0:t.forceOwnership))}function cC(e){cM(e=uZ(e,cE));let t=cS(e),n=e._freezeSettings(),r=new uH;return cx(t,r,new uK(r,n.cacheSizeBytes))}function cx(e,t,n){let r=new nY;return e.asyncQueue.enqueue(async()=>{try{await cu(e,n),await cc(e,t),r.resolve()}catch(i){if(!("FirebaseError"===i.name?i.code===nW.FAILED_PRECONDITION||i.code===nW.UNIMPLEMENTED:!("undefined"!=typeof DOMException&&i instanceof DOMException)||22===i.code||20===i.code||11===i.code))throw i;nz("Error enabling offline persistence. Falling back to persistence disabled: "+i),r.reject(i)}}).then(()=>r.promise)}function cR(e){if(e._initialized&&!e._terminated)throw new nQ(nW.FAILED_PRECONDITION,"Persistence can only be cleared before a Firestore instance is initialized or after it is terminated.");let t=new nY;return e._queue.enqueueAndForgetEvenWhileRestricted(async()=>{try{await async function(e){if(!rw.C())return Promise.resolve();await rw.delete(e+"main")}(o0(e._databaseId,e._persistenceKey)),t.resolve()}catch(n){t.reject(n)}}),t.promise}function cD(e){return function(e){let t=new nY;return e.asyncQueue.enqueueAndForget(async()=>uT(await cg(e),t)),t.promise}(cS(e=uZ(e,cE)))}function cN(e){var t;return(t=cS(e=uZ(e,cE))).asyncQueue.enqueue(async()=>{let e=await cf(t),n=await cm(t);return e.setNetworkEnabled(!0),n._u.delete(0),lR(n)})}function cO(e){var t;return(t=cS(e=uZ(e,cE))).asyncQueue.enqueue(async()=>{let e=await cf(t),n=await cm(t);return e.setNetworkEnabled(!1),async function(e){e._u.add(0),await lD(e),e.gu.set("Offline")}(n)})}function cP(e,t){let n=cS(e=uZ(e,cE)),r=new cI;return function(e,t,n,r){var i,s;let a=(i=lI(t),s=function(e,t){if(e instanceof Uint8Array)return cr(e,t);if(e instanceof ArrayBuffer)return cr(new Uint8Array(e),t);if(e instanceof ReadableStream)return e.getReader();throw Error("Source of `toByteStreamReader` has to be a ArrayBuffer or ReadableStream")}("string"==typeof n?(new TextEncoder).encode(n):n),new cs(s,i));e.asyncQueue.enqueueAndForget(async()=>{!function(e,t,n){(async function(e,t,n){try{var r;let i=await t.getMetadata();if(await function(e,t){let n=sK(t.createTime);return e.persistence.runTransaction("hasNewerBundle","readonly",n=>e.Ns.getBundleMetadata(n,t.id)).then(e=>!!e&&e.createTime.compareTo(n)>=0)}(e.localStore,i))return await t.close(),n._completeWith({taskState:"Success",documentsLoaded:i.totalDocuments,bytesLoaded:i.totalBytes,totalDocuments:i.totalDocuments,totalBytes:i.totalBytes}),Promise.resolve(new Set);n._updateProgress(uo(i));let s=new ua(i,e.localStore,t.yt),a=await t.mc();for(;a;){let o=await s.Fu(a);o&&n._updateProgress(o),a=await t.mc()}let l=await s.complete();return await uR(e,l.Lu,void 0),await (r=e.localStore).persistence.runTransaction("Save bundle","readwrite",e=>r.Ns.saveBundleMetadata(e,i)),n._completeWith(l.progress),Promise.resolve(l.Bu)}catch(u){return nz("SyncEngine",`Loading bundle failed with ${u}`),n._failWith(u),Promise.resolve(new Set)}})(e,t,n).then(t=>{e.sharedClientState.notifyBundleLoaded(t)})}(await cg(e),a,r)})}(n,e._databaseId,t,r),r}function cL(e,t){var n;return(n=cS(e=uZ(e,cE))).asyncQueue.enqueue(async()=>{var e;return(e=await cp(n)).persistence.runTransaction("Get named query","readonly",n=>e.Ns.getNamedQuery(n,t))}).then(t=>t?new u5(e,null,t.query):null)}function cM(e){if(e._initialized||e._terminated)throw new nQ(nW.FAILED_PRECONDITION,"Firestore has already been started and persistence can no longer be enabled. You can only enable persistence before calling any other methods on a Firestore object.")}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *//**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class cF{constructor(e){this._byteString=e}static fromBase64String(e){try{return new cF(rV.fromBase64String(e))}catch(t){throw new nQ(nW.INVALID_ARGUMENT,"Failed to construct data from Base64 string: "+t)}}static fromUint8Array(e){return new cF(rV.fromUint8Array(e))}toBase64(){return this._byteString.toBase64()}toUint8Array(){return this._byteString.toUint8Array()}toString(){return"Bytes(base64: "+this.toBase64()+")"}isEqual(e){return this._byteString.isEqual(e._byteString)}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class cU{constructor(...e){for(let t=0;t<e.length;++t)if(0===e[t].length)throw new nQ(nW.INVALID_ARGUMENT,"Invalid field name at argument $(i + 1). Field names must not be empty.");this._internalPath=new rr(e)}isEqual(e){return this._internalPath.isEqual(e._internalPath)}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class cV{constructor(e){this._methodName=e}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class cq{constructor(e,t){if(!isFinite(e)||e<-90||e>90)throw new nQ(nW.INVALID_ARGUMENT,"Latitude must be a number between -90 and 90, but was: "+e);if(!isFinite(t)||t<-180||t>180)throw new nQ(nW.INVALID_ARGUMENT,"Longitude must be a number between -180 and 180, but was: "+t);this._lat=e,this._long=t}get latitude(){return this._lat}get longitude(){return this._long}isEqual(e){return this._lat===e._lat&&this._long===e._long}toJSON(){return{latitude:this._lat,longitude:this._long}}_compareTo(e){return n5(this._lat,e._lat)||n5(this._long,e._long)}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let cB=/^__.*__$/;class cj{constructor(e,t,n){this.data=e,this.fieldMask=t,this.fieldTransforms=n}toMutation(e,t){return null!==this.fieldMask?new sd(e,this.data,this.fieldMask,t,this.fieldTransforms):new sh(e,this.data,t,this.fieldTransforms)}}class c${constructor(e,t,n){this.data=e,this.fieldMask=t,this.fieldTransforms=n}toMutation(e,t){return new sd(e,this.data,this.fieldMask,t,this.fieldTransforms)}}function cz(e){switch(e){case 0:case 2:case 1:return!0;case 3:case 4:return!1;default:throw nK()}}class cG{constructor(e,t,n,r,i,s){this.settings=e,this.databaseId=t,this.yt=n,this.ignoreUndefinedProperties=r,void 0===i&&this.na(),this.fieldTransforms=i||[],this.fieldMask=s||[]}get path(){return this.settings.path}get sa(){return this.settings.sa}ia(e){return new cG(Object.assign(Object.assign({},this.settings),e),this.databaseId,this.yt,this.ignoreUndefinedProperties,this.fieldTransforms,this.fieldMask)}ra(e){var t;let n=null===(t=this.path)||void 0===t?void 0:t.child(e),r=this.ia({path:n,oa:!1});return r.ua(e),r}ca(e){var t;let n=null===(t=this.path)||void 0===t?void 0:t.child(e),r=this.ia({path:n,oa:!1});return r.na(),r}aa(e){return this.ia({path:void 0,oa:!0})}ha(e){return ht(e,this.settings.methodName,this.settings.la||!1,this.path,this.settings.fa)}contains(e){return void 0!==this.fieldMask.find(t=>e.isPrefixOf(t))||void 0!==this.fieldTransforms.find(t=>e.isPrefixOf(t.field))}na(){if(this.path)for(let e=0;e<this.path.length;e++)this.ua(this.path.get(e))}ua(e){if(0===e.length)throw this.ha("Document fields must not be empty");if(cz(this.sa)&&cB.test(e))throw this.ha('Document fields cannot begin and end with "__"')}}class cK{constructor(e,t,n){this.databaseId=e,this.ignoreUndefinedProperties=t,this.yt=n||lI(e)}da(e,t,n,r=!1){return new cG({sa:e,methodName:t,fa:n,path:rr.emptyPath(),oa:!1,la:r},this.databaseId,this.yt,this.ignoreUndefinedProperties)}}function cH(e){let t=e._freezeSettings(),n=lI(e._databaseId);return new cK(e._databaseId,!!t.ignoreUndefinedProperties,n)}function cW(e,t,n,r,i,s={}){let a,o;let l=e.da(s.merge||s.mergeFields?2:0,t,n,i);c9("Data must be an object, but it was:",l,r);let u=c6(r,l);if(s.merge)a=new iA(l.fieldMask),o=l.fieldTransforms;else if(s.mergeFields){let c=[];for(let h of s.mergeFields){let d=c8(t,h,n);if(!l.contains(d))throw new nQ(nW.INVALID_ARGUMENT,`Field '${d}' is specified in your field mask but missing from your input data.`);hn(c,d)||c.push(d)}a=new iA(c),o=l.fieldTransforms.filter(e=>a.covers(e.field))}else a=null,o=l.fieldTransforms;return new cj(new iC(u),a,o)}class cQ extends cV{_toFieldTransform(e){if(2!==e.sa)throw 1===e.sa?e.ha(`${this._methodName}() can only appear at the top level of your update data`):e.ha(`${this._methodName}() cannot be used with set() unless you pass {merge:true}`);return e.fieldMask.push(e.path),null}isEqual(e){return e instanceof cQ}}function cY(e,t,n){return new cG({sa:3,fa:t.settings.fa,methodName:e._methodName,oa:n},t.databaseId,t.yt,t.ignoreUndefinedProperties)}class cX extends cV{_toFieldTransform(e){return new sr(e.path,new i6)}isEqual(e){return e instanceof cX}}class cJ extends cV{constructor(e,t){super(e),this._a=t}_toFieldTransform(e){let t=cY(this,e,!0),n=this._a.map(e=>c3(e,t)),r=new i5(n);return new sr(e.path,r)}isEqual(e){return this===e}}class cZ extends cV{constructor(e,t){super(e),this._a=t}_toFieldTransform(e){let t=cY(this,e,!0),n=this._a.map(e=>c3(e,t)),r=new i8(n);return new sr(e.path,r)}isEqual(e){return this===e}}class c0 extends cV{constructor(e,t){super(e),this.wa=t}_toFieldTransform(e){let t=new se(e.yt,i2(e.yt,this.wa));return new sr(e.path,t)}isEqual(e){return this===e}}function c1(e,t,n,r){let i=e.da(1,t,n);c9("Data must be an object, but it was:",i,r);let s=[],a=iC.empty();rO(r,(e,r)=>{let o=he(t,e,n);r=(0,p.m9)(r);let l=i.ca(o);if(r instanceof cQ)s.push(o);else{let u=c3(r,l);null!=u&&(s.push(o),a.set(o,u))}});let o=new iA(s);return new c$(a,o,i.fieldTransforms)}function c2(e,t,n,r,i,s){let a=e.da(1,t,n),o=[c8(t,r,n)],l=[i];if(s.length%2!=0)throw new nQ(nW.INVALID_ARGUMENT,`Function ${t}() needs to be called with an even number of arguments that alternate between field names and values.`);for(let u=0;u<s.length;u+=2)o.push(c8(t,s[u])),l.push(s[u+1]);let c=[],h=iC.empty();for(let d=o.length-1;d>=0;--d)if(!hn(c,o[d])){let f=o[d],m=l[d];m=(0,p.m9)(m);let g=a.ca(f);if(m instanceof cQ)c.push(f);else{let y=c3(m,g);null!=y&&(c.push(f),h.set(f,y))}}let v=new iA(c);return new c$(h,v,a.fieldTransforms)}function c4(e,t,n,r=!1){return c3(n,e.da(r?4:3,t))}function c3(e,t){if(c5(e=(0,p.m9)(e)))return c9("Unsupported field value:",t,e),c6(e,t);if(e instanceof cV)return function(e,t){if(!cz(t.sa))throw t.ha(`${e._methodName}() can only be used with update() and set()`);if(!t.path)throw t.ha(`${e._methodName}() is not currently supported inside arrays`);let n=e._toFieldTransform(t);n&&t.fieldTransforms.push(n)}(e,t),null;if(void 0===e&&t.ignoreUndefinedProperties)return null;if(t.path&&t.fieldMask.push(t.path),e instanceof Array){if(t.settings.oa&&4!==t.sa)throw t.ha("Nested arrays are not supported");return function(e,t){let n=[],r=0;for(let i of e){let s=c3(i,t.aa(r));null==s&&(s={nullValue:"NULL_VALUE"}),n.push(s),r++}return{arrayValue:{values:n}}}(e,t)}return function(e,t){if(null===(e=(0,p.m9)(e)))return{nullValue:"NULL_VALUE"};if("number"==typeof e)return i2(t.yt,e);if("boolean"==typeof e)return{booleanValue:e};if("string"==typeof e)return{stringValue:e};if(e instanceof Date){let n=n8.fromDate(e);return{timestampValue:sz(t.yt,n)}}if(e instanceof n8){let r=new n8(e.seconds,1e3*Math.floor(e.nanoseconds/1e3));return{timestampValue:sz(t.yt,r)}}if(e instanceof cq)return{geoPointValue:{latitude:e.latitude,longitude:e.longitude}};if(e instanceof cF)return{bytesValue:sG(t.yt,e._byteString)};if(e instanceof u6){let i=t.databaseId,s=e.firestore._databaseId;if(!s.isEqual(i))throw t.ha(`Document reference is for database ${s.projectId}/${s.database} but should be for database ${i.projectId}/${i.database}`);return{referenceValue:sH(e.firestore._databaseId||t.databaseId,e._key.path)}}throw t.ha(`Unsupported field value: ${uJ(e)}`)}(e,t)}function c6(e,t){let n={};return rP(e)?t.path&&t.path.length>0&&t.fieldMask.push(t.path):rO(e,(e,r)=>{let i=c3(r,t.ra(e));null!=i&&(n[e]=i)}),{mapValue:{fields:n}}}function c5(e){return!("object"!=typeof e||null===e||e instanceof Array||e instanceof Date||e instanceof n8||e instanceof cq||e instanceof cF||e instanceof u6||e instanceof cV)}function c9(e,t,n){if(!c5(n)||!("object"==typeof n&&null!==n&&(Object.getPrototypeOf(n)===Object.prototype||null===Object.getPrototypeOf(n)))){let r=uJ(n);throw"an object"===r?t.ha(e+" a custom object"):t.ha(e+" "+r)}}function c8(e,t,n){if((t=(0,p.m9)(t))instanceof cU)return t._internalPath;if("string"==typeof t)return he(e,t);throw ht("Field path arguments must be of type string or ",e,!1,void 0,n)}let c7=RegExp("[~\\*/\\[\\]]");function he(e,t,n){if(t.search(c7)>=0)throw ht(`Invalid field path (${t}). Paths must not contain '~', '*', '/', '[', or ']'`,e,!1,void 0,n);try{return new cU(...t.split("."))._internalPath}catch(r){throw ht(`Invalid field path (${t}). Paths must not be empty, begin with '.', end with '.', or contain '..'`,e,!1,void 0,n)}}function ht(e,t,n,r,i){let s=r&&!r.isEmpty(),a=void 0!==i,o=`Function ${t}() called with invalid data`;n&&(o+=" (via `toFirestore()`)"),o+=". ";let l="";return(s||a)&&(l+=" (found",s&&(l+=` in field ${r}`),a&&(l+=` in document ${i}`),l+=")"),new nQ(nW.INVALID_ARGUMENT,o+e+l)}function hn(e,t){return e.some(e=>e.isEqual(t))}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class hr{constructor(e,t,n,r,i){this._firestore=e,this._userDataWriter=t,this._key=n,this._document=r,this._converter=i}get id(){return this._key.path.lastSegment()}get ref(){return new u6(this._firestore,this._converter,this._key)}exists(){return null!==this._document}data(){if(this._document){if(this._converter){let e=new hi(this._firestore,this._userDataWriter,this._key,this._document,null);return this._converter.fromFirestore(e)}return this._userDataWriter.convertValue(this._document.data.value)}}get(e){if(this._document){let t=this._document.data.field(hs("DocumentSnapshot.get",e));if(null!==t)return this._userDataWriter.convertValue(t)}}}class hi extends hr{data(){return super.data()}}function hs(e,t){return"string"==typeof t?he(e,t):t instanceof cU?t._internalPath:t._delegate._internalPath}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function ha(e){if("L"===e.limitType&&0===e.explicitOrderBy.length)throw new nQ(nW.UNIMPLEMENTED,"limitToLast() queries require specifying at least one orderBy() clause")}class ho{}class hl extends ho{}function hu(e,t,...n){let r=[];for(let i of(t instanceof ho&&r.push(t),function(e){let t=e.filter(e=>e instanceof hd).length,n=e.filter(e=>e instanceof hc).length;if(t>1||t>0&&n>0)throw new nQ(nW.INVALID_ARGUMENT,"InvalidQuery. When using composite filters, you cannot use more than one filter at the top level. Consider nesting the multiple filters within an `and(...)` statement. For example: change `query(query, where(...), or(...))` to `query(query, and(where(...), or(...)))`.")}(r=r.concat(n)),r))e=i._apply(e);return e}class hc extends hl{constructor(e,t,n){super(),this._field=e,this._op=t,this._value=n,this.type="where"}static _create(e,t,n){return new hc(e,t,n)}_apply(e){let t=this._parse(e);return hA(e._query,t),new u5(e.firestore,e.converter,iK(e._query,t))}_parse(e){let t=cH(e.firestore),n=function(e,t,n,r,i,s,a){let o;if(i.isKeyField()){if("array-contains"===s||"array-contains-any"===s)throw new nQ(nW.INVALID_ARGUMENT,`Invalid Query. You can't perform '${s}' queries on documentId().`);if("in"===s||"not-in"===s){hk(a,s);let l=[];for(let u of a)l.push(hS(r,e,u));o={arrayValue:{values:l}}}else o=hS(r,e,a)}else"in"!==s&&"not-in"!==s&&"array-contains-any"!==s||hk(a,s),o=c4(n,t,a,"in"===s||"not-in"===s);return is.create(i,s,o)}(e._query,"where",t,e.firestore._databaseId,this._field,this._op,this._value);return n}}function hh(e,t,n){let r=hs("where",e);return hc._create(r,t,n)}class hd extends ho{constructor(e,t){super(),this.type=e,this._queryConstraints=t}static _create(e,t){return new hd(e,t)}_parse(e){let t=this._queryConstraints.map(t=>t._parse(e)).filter(e=>e.getFilters().length>0);return 1===t.length?t[0]:ia.create(t,this._getOperator())}_apply(e){let t=this._parse(e);return 0===t.getFilters().length?e:(function(e,t){let n=e,r=t.getFlattenedFilters();for(let i of r)hA(n,i),n=iK(n,i)}(e._query,t),new u5(e.firestore,e.converter,iK(e._query,t)))}_getQueryConstraints(){return this._queryConstraints}_getOperator(){return"and"===this.type?"and":"or"}}class hf extends hl{constructor(e,t){super(),this._field=e,this._direction=t,this.type="orderBy"}static _create(e,t){return new hf(e,t)}_apply(e){let t=function(e,t,n){if(null!==e.startAt)throw new nQ(nW.INVALID_ARGUMENT,"Invalid query. You must not call startAt() or startAfter() before calling orderBy().");if(null!==e.endAt)throw new nQ(nW.INVALID_ARGUMENT,"Invalid query. You must not call endAt() or endBefore() before calling orderBy().");let r=new i_(t,n);return function(e,t){if(null===iB(e)){let n=ij(e);null!==n&&hC(e,n,t.field)}}(e,r),r}(e._query,this._field,this._direction);return new u5(e.firestore,e.converter,function(e,t){let n=e.explicitOrderBy.concat([t]);return new iU(e.path,e.collectionGroup,n,e.filters.slice(),e.limit,e.limitType,e.startAt,e.endAt)}(e._query,t))}}function hp(e,t="asc"){let n=hs("orderBy",e);return hf._create(n,t)}class hm extends hl{constructor(e,t,n){super(),this.type=e,this._limit=t,this._limitType=n}static _create(e,t,n){return new hm(e,t,n)}_apply(e){return new u5(e.firestore,e.converter,iH(e._query,this._limit,this._limitType))}}function hg(e){return u0("limit",e),hm._create("limit",e,"F")}function hy(e){return u0("limitToLast",e),hm._create("limitToLast",e,"L")}class hv extends hl{constructor(e,t,n){super(),this.type=e,this._docOrFields=t,this._inclusive=n}static _create(e,t,n){return new hv(e,t,n)}_apply(e){var t;let n=hE(e,this.type,this._docOrFields,this._inclusive);return new u5(e.firestore,e.converter,(t=e._query,new iU(t.path,t.collectionGroup,t.explicitOrderBy.slice(),t.filters.slice(),t.limit,t.limitType,n,t.endAt)))}}function hw(...e){return hv._create("startAt",e,!0)}function h_(...e){return hv._create("startAfter",e,!1)}class hb extends hl{constructor(e,t,n){super(),this.type=e,this._docOrFields=t,this._inclusive=n}static _create(e,t,n){return new hb(e,t,n)}_apply(e){var t;let n=hE(e,this.type,this._docOrFields,this._inclusive);return new u5(e.firestore,e.converter,(t=e._query,new iU(t.path,t.collectionGroup,t.explicitOrderBy.slice(),t.filters.slice(),t.limit,t.limitType,t.startAt,n)))}}function hI(...e){return hb._create("endBefore",e,!1)}function hT(...e){return hb._create("endAt",e,!0)}function hE(e,t,n,r){if(n[0]=(0,p.m9)(n[0]),n[0]instanceof hr)return function(e,t,n,r,i){if(!r)throw new nQ(nW.NOT_FOUND,`Can't use a DocumentSnapshot that doesn't exist for ${n}().`);let s=[];for(let a of iz(e))if(a.field.isKeyField())s.push(r0(t,r.key));else{let o=r.data.field(a.field);if(rz(o))throw new nQ(nW.INVALID_ARGUMENT,'Invalid query. You are trying to start or end a query using a document for which the field "'+a.field+'" is an uncommitted server timestamp. (Since the value of this field is unknown, you cannot start/end a query with it.)');if(null===o){let l=a.field.canonicalString();throw new nQ(nW.INVALID_ARGUMENT,`Invalid query. You are trying to start or end a query using a document for which the field '${l}' (used as the orderBy) does not exist.`)}s.push(o)}return new ie(s,i)}(e._query,e.firestore._databaseId,t,n[0]._document,r);{let i=cH(e.firestore);return function(e,t,n,r,i,s){let a=e.explicitOrderBy;if(i.length>a.length)throw new nQ(nW.INVALID_ARGUMENT,`Too many arguments provided to ${r}(). The number of arguments must be less than or equal to the number of orderBy() clauses`);let o=[];for(let l=0;l<i.length;l++){let u=i[l];if(a[l].field.isKeyField()){if("string"!=typeof u)throw new nQ(nW.INVALID_ARGUMENT,`Invalid query. Expected a string for document ID in ${r}(), but got a ${typeof u}`);if(!i$(e)&&-1!==u.indexOf("/"))throw new nQ(nW.INVALID_ARGUMENT,`Invalid query. When querying a collection and ordering by documentId(), the value passed to ${r}() must be a plain document ID, but '${u}' contains a slash.`);let c=e.path.child(rt.fromString(u));if(!ri.isDocumentKey(c))throw new nQ(nW.INVALID_ARGUMENT,`Invalid query. When querying a collection group and ordering by documentId(), the value passed to ${r}() must result in a valid document path, but '${c}' is not because it contains an odd number of segments.`);let h=new ri(c);o.push(r0(t,h))}else{let d=c4(n,r,u);o.push(d)}}return new ie(o,s)}(e._query,e.firestore._databaseId,i,t,n,r)}}function hS(e,t,n){if("string"==typeof(n=(0,p.m9)(n))){if(""===n)throw new nQ(nW.INVALID_ARGUMENT,"Invalid query. When querying with documentId(), you must provide a valid document ID, but it was an empty string.");if(!i$(t)&&-1!==n.indexOf("/"))throw new nQ(nW.INVALID_ARGUMENT,`Invalid query. When querying a collection by documentId(), you must provide a plain document ID, but '${n}' contains a '/' character.`);let r=t.path.child(rt.fromString(n));if(!ri.isDocumentKey(r))throw new nQ(nW.INVALID_ARGUMENT,`Invalid query. When querying a collection group by documentId(), the value provided must result in a valid document path, but '${r}' is not because it has an odd number of segments (${r.length}).`);return r0(e,new ri(r))}if(n instanceof u6)return r0(e,n._key);throw new nQ(nW.INVALID_ARGUMENT,`Invalid query. When querying with documentId(), you must provide a valid string or a DocumentReference, but it was: ${uJ(n)}.`)}function hk(e,t){if(!Array.isArray(e)||0===e.length)throw new nQ(nW.INVALID_ARGUMENT,`Invalid Query. A non-empty array is required for '${t.toString()}' filters.`);if(e.length>10)throw new nQ(nW.INVALID_ARGUMENT,`Invalid Query. '${t.toString()}' filters support a maximum of 10 elements in the value array.`)}function hA(e,t){if(t.isInequality()){let n=ij(e),r=t.field;if(null!==n&&!n.isEqual(r))throw new nQ(nW.INVALID_ARGUMENT,`Invalid query. All where filters with an inequality (<, <=, !=, not-in, >, or >=) must be on the same field. But you have inequality filters on '${n.toString()}' and '${r.toString()}'`);let i=iB(e);null!==i&&hC(e,r,i)}let s=function(e,t){for(let n of e)for(let r of n.getFlattenedFilters())if(t.indexOf(r.op)>=0)return r.op;return null}(e.filters,function(e){switch(e){case"!=":return["!=","not-in"];case"array-contains":return["array-contains","array-contains-any","not-in"];case"in":return["array-contains-any","in","not-in"];case"array-contains-any":return["array-contains","array-contains-any","in","not-in"];case"not-in":return["array-contains","array-contains-any","in","not-in","!="];default:return[]}}(t.op));if(null!==s)throw s===t.op?new nQ(nW.INVALID_ARGUMENT,`Invalid query. You cannot use more than one '${t.op.toString()}' filter.`):new nQ(nW.INVALID_ARGUMENT,`Invalid query. You cannot use '${t.op.toString()}' filters with '${s.toString()}' filters.`)}function hC(e,t,n){if(!n.isEqual(t))throw new nQ(nW.INVALID_ARGUMENT,`Invalid query. You have a where filter with an inequality (<, <=, !=, not-in, >, or >=) on field '${t.toString()}' and so you must also use '${t.toString()}' as your first argument to orderBy(), but your first orderBy() is on field '${n.toString()}' instead.`)}class hx{convertValue(e,t="none"){switch(rW(e)){case 0:return null;case 1:return e.booleanValue;case 2:return rj(e.integerValue||e.doubleValue);case 3:return this.convertTimestamp(e.timestampValue);case 4:return this.convertServerTimestamp(e,t);case 5:return e.stringValue;case 6:return this.convertBytes(r$(e.bytesValue));case 7:return this.convertReference(e.referenceValue);case 8:return this.convertGeoPoint(e.geoPointValue);case 9:return this.convertArray(e.arrayValue,t);case 10:return this.convertObject(e.mapValue,t);default:throw nK()}}convertObject(e,t){let n={};return rO(e.fields,(e,r)=>{n[e]=this.convertValue(r,t)}),n}convertGeoPoint(e){return new cq(rj(e.latitude),rj(e.longitude))}convertArray(e,t){return(e.values||[]).map(e=>this.convertValue(e,t))}convertServerTimestamp(e,t){switch(t){case"previous":let n=function e(t){let n=t.mapValue.fields.__previous_value__;return rz(n)?e(n):n}(e);return null==n?null:this.convertValue(n,t);case"estimate":return this.convertTimestamp(rG(e));default:return null}}convertTimestamp(e){let t=rB(e);return new n8(t.seconds,t.nanos)}convertDocumentKey(e,t){let n=rt.fromString(e);ae(n)||nK();let r=new rD(n.get(1),n.get(3)),i=new ri(n.popFirst(5));return r.isEqual(t)||n$(`Document ${i} contains a document reference within a different database (${r.projectId}/${r.database}) which is not supported. It will be treated as a reference in the current database (${t.projectId}/${t.database}) instead.`),i}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function hR(e,t,n){return e?n&&(n.merge||n.mergeFields)?e.toFirestore(t,n):e.toFirestore(t):t}class hD extends hx{constructor(e){super(),this.firestore=e}convertBytes(e){return new cF(e)}convertReference(e){let t=this.convertDocumentKey(e,this.firestore._databaseId);return new u6(this.firestore,null,t)}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class hN{constructor(e,t){this.hasPendingWrites=e,this.fromCache=t}isEqual(e){return this.hasPendingWrites===e.hasPendingWrites&&this.fromCache===e.fromCache}}class hO extends hr{constructor(e,t,n,r,i,s){super(e,t,n,r,s),this._firestore=e,this._firestoreImpl=e,this.metadata=i}exists(){return super.exists()}data(e={}){if(this._document){if(this._converter){let t=new hP(this._firestore,this._userDataWriter,this._key,this._document,this.metadata,null);return this._converter.fromFirestore(t,e)}return this._userDataWriter.convertValue(this._document.data.value,e.serverTimestamps)}}get(e,t={}){if(this._document){let n=this._document.data.field(hs("DocumentSnapshot.get",e));if(null!==n)return this._userDataWriter.convertValue(n,t.serverTimestamps)}}}class hP extends hO{data(e={}){return super.data(e)}}class hL{constructor(e,t,n,r){this._firestore=e,this._userDataWriter=t,this._snapshot=r,this.metadata=new hN(r.hasPendingWrites,r.fromCache),this.query=n}get docs(){let e=[];return this.forEach(t=>e.push(t)),e}get size(){return this._snapshot.docs.size}get empty(){return 0===this.size}forEach(e,t){this._snapshot.docs.forEach(n=>{e.call(t,new hP(this._firestore,this._userDataWriter,n.key,n,new hN(this._snapshot.mutatedKeys.has(n.key),this._snapshot.fromCache),this.query.converter))})}docChanges(e={}){let t=!!e.includeMetadataChanges;if(t&&this._snapshot.excludesMetadataChanges)throw new nQ(nW.INVALID_ARGUMENT,"To include metadata changes with your document changes, you must also pass { includeMetadataChanges:true } to onSnapshot().");return this._cachedChanges&&this._cachedChangesIncludeMetadataChanges===t||(this._cachedChanges=function(e,t){if(e._snapshot.oldDocs.isEmpty()){let n=0;return e._snapshot.docChanges.map(t=>{let r=new hP(e._firestore,e._userDataWriter,t.doc.key,t.doc,new hN(e._snapshot.mutatedKeys.has(t.doc.key),e._snapshot.fromCache),e.query.converter);return t.doc,{type:"added",doc:r,oldIndex:-1,newIndex:n++}})}{let r=e._snapshot.oldDocs;return e._snapshot.docChanges.filter(e=>t||3!==e.type).map(t=>{let n=new hP(e._firestore,e._userDataWriter,t.doc.key,t.doc,new hN(e._snapshot.mutatedKeys.has(t.doc.key),e._snapshot.fromCache),e.query.converter),i=-1,s=-1;return 0!==t.type&&(i=r.indexOf(t.doc.key),r=r.delete(t.doc.key)),1!==t.type&&(s=(r=r.add(t.doc)).indexOf(t.doc.key)),{type:function(e){switch(e){case 0:return"added";case 2:case 3:return"modified";case 1:return"removed";default:return nK()}}(t.type),doc:n,oldIndex:i,newIndex:s}})}}(this,t),this._cachedChangesIncludeMetadataChanges=t),this._cachedChanges}}function hM(e,t){return e instanceof hO&&t instanceof hO?e._firestore===t._firestore&&e._key.isEqual(t._key)&&(null===e._document?null===t._document:e._document.isEqual(t._document))&&e._converter===t._converter:e instanceof hL&&t instanceof hL&&e._firestore===t._firestore&&cn(e.query,t.query)&&e.metadata.isEqual(t.metadata)&&e._snapshot.isEqual(t._snapshot)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function hF(e){e=uZ(e,u6);let t=uZ(e.firestore,cE);return cv(cS(t),e._key).then(n=>hX(t,e,n))}class hU extends hx{constructor(e){super(),this.firestore=e}convertBytes(e){return new cF(e)}convertReference(e){let t=this.convertDocumentKey(e,this.firestore._databaseId);return new u6(this.firestore,null,t)}}function hV(e){e=uZ(e,u6);let t=uZ(e.firestore,cE),n=cS(t),r=new hU(t);return(function(e,t){let n=new nY;return e.asyncQueue.enqueueAndForget(async()=>(async function(e,t,n){try{let r=await e.persistence.runTransaction("read document","readonly",n=>e.localDocuments.getDocument(n,t));r.isFoundDocument()?n.resolve(r):r.isNoDocument()?n.resolve(null):n.reject(new nQ(nW.UNAVAILABLE,"Failed to get document from cache. (However, this document may exist on the server. Run again without setting 'source' in the GetOptions to attempt to retrieve the document from the server.)"))}catch(s){let i=l2(s,`Failed to get document '${t} from cache`);n.reject(i)}})(await cp(e),t,n)),n.promise})(n,e._key).then(n=>new hO(t,r,e._key,n,new hN(null!==n&&n.hasLocalMutations,!0),e.converter))}function hq(e){e=uZ(e,u6);let t=uZ(e.firestore,cE);return cv(cS(t),e._key,{source:"server"}).then(n=>hX(t,e,n))}function hB(e){e=uZ(e,u5);let t=uZ(e.firestore,cE),n=cS(t),r=new hU(t);return ha(e._query),cw(n,e._query).then(n=>new hL(t,r,e,n))}function hj(e){e=uZ(e,u5);let t=uZ(e.firestore,cE),n=cS(t),r=new hU(t);return(function(e,t){let n=new nY;return e.asyncQueue.enqueueAndForget(async()=>(async function(e,t,n){try{let r=await o7(e,t,!0),i=new uc(t,r.Hi),s=i.Wu(r.documents),a=i.applyChanges(s,!1);n.resolve(a.snapshot)}catch(l){let o=l2(l,`Failed to execute query '${t} against cache`);n.reject(o)}})(await cp(e),t,n)),n.promise})(n,e._query).then(n=>new hL(t,r,e,n))}function h$(e){e=uZ(e,u5);let t=uZ(e.firestore,cE),n=cS(t),r=new hU(t);return cw(n,e._query,{source:"server"}).then(n=>new hL(t,r,e,n))}function hz(e,t,n){e=uZ(e,u6);let r=uZ(e.firestore,cE),i=hR(e.converter,t,n);return hY(r,[cW(cH(r),"setDoc",e._key,i,null!==e.converter,n).toMutation(e._key,ss.none())])}function hG(e,t,n,...r){let i;e=uZ(e,u6);let s=uZ(e.firestore,cE),a=cH(s);return i="string"==typeof(t=(0,p.m9)(t))||t instanceof cU?c2(a,"updateDoc",e._key,t,n,r):c1(a,"updateDoc",e._key,t),hY(s,[i.toMutation(e._key,ss.exists(!0))])}function hK(e){return hY(uZ(e.firestore,cE),[new sg(e._key,ss.none())])}function hH(e,t){let n=uZ(e.firestore,cE),r=ce(e),i=hR(e.converter,t);return hY(n,[cW(cH(e.firestore),"addDoc",r._key,i,null!==e.converter,{}).toMutation(r._key,ss.exists(!1))]).then(()=>r)}function hW(e,...t){var n,r,i;let s,a,o;e=(0,p.m9)(e);let l={includeMetadataChanges:!1},u=0;"object"!=typeof t[0]||cb(t[u])||(l=t[u],u++);let c={includeMetadataChanges:l.includeMetadataChanges};if(cb(t[u])){let h=t[u];t[u]=null===(n=h.next)||void 0===n?void 0:n.bind(h),t[u+1]=null===(r=h.error)||void 0===r?void 0:r.bind(h),t[u+2]=null===(i=h.complete)||void 0===i?void 0:i.bind(h)}if(e instanceof u6)a=uZ(e.firestore,cE),o=iV(e._key.path),s={next:n=>{t[u]&&t[u](hX(a,e,n))},error:t[u+1],complete:t[u+2]};else{let d=uZ(e,u5);a=uZ(d.firestore,cE),o=d._query;let f=new hU(a);s={next:e=>{t[u]&&t[u](new hL(a,f,d,e))},error:t[u+1],complete:t[u+2]},ha(e._query)}return function(e,t,n,r){let i=new ci(r),s=new ur(t,i,n);return e.asyncQueue.enqueueAndForget(async()=>l8(await cy(e),s)),()=>{i.bc(),e.asyncQueue.enqueueAndForget(async()=>l7(await cy(e),s))}}(cS(a),o,c,s)}function hQ(e,t){return function(e,t){let n=new ci(t);return e.asyncQueue.enqueueAndForget(async()=>{(await cy(e)).Ru.add(n),n.next()}),()=>{n.bc(),e.asyncQueue.enqueueAndForget(async()=>(function(e,t){e.Ru.delete(t)})(await cy(e),n))}}(cS(e=uZ(e,cE)),cb(t)?t:{next:t})}function hY(e,t){return function(e,t){let n=new nY;return e.asyncQueue.enqueueAndForget(async()=>uy(await cg(e),t,n)),n.promise}(cS(e),t)}function hX(e,t,n){let r=n.docs.get(t._key),i=new hU(e);return new hO(e,i,t._key,r,new hN(n.hasPendingWrites,n.fromCache),t.converter)}/**
 * @license
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let hJ={maxAttempts:5};/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class hZ{constructor(e,t){this._firestore=e,this._commitHandler=t,this._mutations=[],this._committed=!1,this._dataReader=cH(e)}set(e,t,n){this._verifyNotCommitted();let r=h0(e,this._firestore),i=hR(r.converter,t,n),s=cW(this._dataReader,"WriteBatch.set",r._key,i,null!==r.converter,n);return this._mutations.push(s.toMutation(r._key,ss.none())),this}update(e,t,n,...r){let i;this._verifyNotCommitted();let s=h0(e,this._firestore);return i="string"==typeof(t=(0,p.m9)(t))||t instanceof cU?c2(this._dataReader,"WriteBatch.update",s._key,t,n,r):c1(this._dataReader,"WriteBatch.update",s._key,t),this._mutations.push(i.toMutation(s._key,ss.exists(!0))),this}delete(e){this._verifyNotCommitted();let t=h0(e,this._firestore);return this._mutations=this._mutations.concat(new sg(t._key,ss.none())),this}commit(){return this._verifyNotCommitted(),this._committed=!0,this._mutations.length>0?this._commitHandler(this._mutations):Promise.resolve()}_verifyNotCommitted(){if(this._committed)throw new nQ(nW.FAILED_PRECONDITION,"A write batch can no longer be used after commit() has been called.")}}function h0(e,t){if((e=(0,p.m9)(e)).firestore!==t)throw new nQ(nW.INVALID_ARGUMENT,"Provided document reference is from a different Firestore instance.");return e}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *//**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class h1 extends class{constructor(e,t){this._firestore=e,this._transaction=t,this._dataReader=cH(e)}get(e){let t=h0(e,this._firestore),n=new hD(this._firestore);return this._transaction.lookup([t._key]).then(e=>{if(!e||1!==e.length)return nK();let r=e[0];if(r.isFoundDocument())return new hr(this._firestore,n,r.key,r,t.converter);if(r.isNoDocument())return new hr(this._firestore,n,t._key,null,t.converter);throw nK()})}set(e,t,n){let r=h0(e,this._firestore),i=hR(r.converter,t,n),s=cW(this._dataReader,"Transaction.set",r._key,i,null!==r.converter,n);return this._transaction.set(r._key,s),this}update(e,t,n,...r){let i;let s=h0(e,this._firestore);return i="string"==typeof(t=(0,p.m9)(t))||t instanceof cU?c2(this._dataReader,"Transaction.update",s._key,t,n,r):c1(this._dataReader,"Transaction.update",s._key,t),this._transaction.update(s._key,i),this}delete(e){let t=h0(e,this._firestore);return this._transaction.delete(t._key),this}}{constructor(e,t){super(e,t),this._firestore=e}get(e){let t=h0(e,this._firestore),n=new hU(this._firestore);return super.get(e).then(e=>new hO(this._firestore,n,t._key,e._document,new hN(!1,!1),t.converter))}}function h2(e,t,n){e=uZ(e,cE);let r=Object.assign(Object.assign({},hJ),n);return!function(e){if(e.maxAttempts<1)throw new nQ(nW.INVALID_ARGUMENT,"Max attempts must be at least 1")}(r),function(e,t,n){let r=new nY;return e.asyncQueue.enqueueAndForget(async()=>{let i=await cd(e).then(e=>e.datastore);new co(e.asyncQueue,i,n,t,r).run()}),r.promise}(cS(e),n=>t(new h1(e,n)),r)}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function h4(){return new cQ("deleteField")}function h3(){return new cX("serverTimestamp")}function h6(...e){return new cJ("arrayUnion",e)}function h5(...e){return new cZ("arrayRemove",e)}function h9(e){return new c0("increment",e)}!function(e,t=!0){nU=h.SDK_VERSION,(0,h._registerComponent)(new d.wA("firestore",(e,{instanceIdentifier:n,options:r})=>{let i=e.getProvider("app").getImmediate(),s=new cE(new n0(e.getProvider("auth-internal")),new n3(e.getProvider("app-check-internal")),function(e,t){if(!Object.prototype.hasOwnProperty.apply(e.options,["projectId"]))throw new nQ(nW.INVALID_ARGUMENT,'"projectId" not provided in firebase.initializeApp.');return new rD(e.options.projectId,t)}(i,n),i);return r=Object.assign({useFetchStreams:t},r),s._setSettings(r),s},"PUBLIC").setMultipleInstances(!0)),(0,h.registerVersion)(nM,"3.8.0",void 0),(0,h.registerVersion)(nM,"3.8.0","esm2017")}()},4444:function(e,t,n){"use strict";n.d(t,{$s:function(){return B},BH:function(){return A},G6:function(){return y},L:function(){return l},LL:function(){return R},Pz:function(){return k},Sg:function(){return C},UG:function(){return d},ZB:function(){return function e(t,n){if(!(n instanceof Object))return n;switch(n.constructor){case Date:return new Date(n.getTime());case Object:void 0===t&&(t={});break;case Array:t=[];break;default:return n}for(let r in n)n.hasOwnProperty(r)&&"__proto__"!==r&&(t[r]=e(t[r],n[r]));return t}},ZR:function(){return x},aH:function(){return S},b$:function(){return m},eu:function(){return w},hl:function(){return v},jU:function(){return f},m9:function(){return j},ne:function(){return U},pd:function(){return F},r3:function(){return N},ru:function(){return p},tV:function(){return u},uI:function(){return h},vZ:function(){return function e(t,n){if(t===n)return!0;let r=Object.keys(t),i=Object.keys(n);for(let s of r){if(!i.includes(s))return!1;let a=t[s],o=n[s];if(P(a)&&P(o)){if(!e(a,o))return!1}else if(a!==o)return!1}for(let l of i)if(!r.includes(l))return!1;return!0}},w1:function(){return g},xO:function(){return L},xb:function(){return O},z$:function(){return c},zI:function(){return _},zd:function(){return M}});var r=n(3454);/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let i=function(e){let t=[],n=0;for(let r=0;r<e.length;r++){let i=e.charCodeAt(r);i<128?t[n++]=i:i<2048?(t[n++]=i>>6|192,t[n++]=63&i|128):(64512&i)==55296&&r+1<e.length&&(64512&e.charCodeAt(r+1))==56320?(i=65536+((1023&i)<<10)+(1023&e.charCodeAt(++r)),t[n++]=i>>18|240,t[n++]=i>>12&63|128,t[n++]=i>>6&63|128,t[n++]=63&i|128):(t[n++]=i>>12|224,t[n++]=i>>6&63|128,t[n++]=63&i|128)}return t},s=function(e){let t=[],n=0,r=0;for(;n<e.length;){let i=e[n++];if(i<128)t[r++]=String.fromCharCode(i);else if(i>191&&i<224){let s=e[n++];t[r++]=String.fromCharCode((31&i)<<6|63&s)}else if(i>239&&i<365){let a=e[n++],o=e[n++],l=e[n++],u=((7&i)<<18|(63&a)<<12|(63&o)<<6|63&l)-65536;t[r++]=String.fromCharCode(55296+(u>>10)),t[r++]=String.fromCharCode(56320+(1023&u))}else{let c=e[n++],h=e[n++];t[r++]=String.fromCharCode((15&i)<<12|(63&c)<<6|63&h)}}return t.join("")},a={byteToCharMap_:null,charToByteMap_:null,byteToCharMapWebSafe_:null,charToByteMapWebSafe_:null,ENCODED_VALS_BASE:"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",get ENCODED_VALS(){return this.ENCODED_VALS_BASE+"+/="},get ENCODED_VALS_WEBSAFE(){return this.ENCODED_VALS_BASE+"-_."},HAS_NATIVE_SUPPORT:"function"==typeof atob,encodeByteArray(e,t){if(!Array.isArray(e))throw Error("encodeByteArray takes an array as a parameter");this.init_();let n=t?this.byteToCharMapWebSafe_:this.byteToCharMap_,r=[];for(let i=0;i<e.length;i+=3){let s=e[i],a=i+1<e.length,o=a?e[i+1]:0,l=i+2<e.length,u=l?e[i+2]:0,c=s>>2,h=(3&s)<<4|o>>4,d=(15&o)<<2|u>>6,f=63&u;l||(f=64,a||(d=64)),r.push(n[c],n[h],n[d],n[f])}return r.join("")},encodeString(e,t){return this.HAS_NATIVE_SUPPORT&&!t?btoa(e):this.encodeByteArray(i(e),t)},decodeString(e,t){return this.HAS_NATIVE_SUPPORT&&!t?atob(e):s(this.decodeStringToByteArray(e,t))},decodeStringToByteArray(e,t){this.init_();let n=t?this.charToByteMapWebSafe_:this.charToByteMap_,r=[];for(let i=0;i<e.length;){let s=n[e.charAt(i++)],a=i<e.length,o=a?n[e.charAt(i)]:0;++i;let l=i<e.length,u=l?n[e.charAt(i)]:64;++i;let c=i<e.length,h=c?n[e.charAt(i)]:64;if(++i,null==s||null==o||null==u||null==h)throw Error();let d=s<<2|o>>4;if(r.push(d),64!==u){let f=o<<4&240|u>>2;if(r.push(f),64!==h){let p=u<<6&192|h;r.push(p)}}}return r},init_(){if(!this.byteToCharMap_){this.byteToCharMap_={},this.charToByteMap_={},this.byteToCharMapWebSafe_={},this.charToByteMapWebSafe_={};for(let e=0;e<this.ENCODED_VALS.length;e++)this.byteToCharMap_[e]=this.ENCODED_VALS.charAt(e),this.charToByteMap_[this.byteToCharMap_[e]]=e,this.byteToCharMapWebSafe_[e]=this.ENCODED_VALS_WEBSAFE.charAt(e),this.charToByteMapWebSafe_[this.byteToCharMapWebSafe_[e]]=e,e>=this.ENCODED_VALS_BASE.length&&(this.charToByteMap_[this.ENCODED_VALS_WEBSAFE.charAt(e)]=e,this.charToByteMapWebSafe_[this.ENCODED_VALS.charAt(e)]=e)}}},o=function(e){let t=i(e);return a.encodeByteArray(t,!0)},l=function(e){return o(e).replace(/\./g,"")},u=function(e){try{return a.decodeString(e,!0)}catch(t){console.error("base64Decode failed: ",t)}return null};/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function c(){return"undefined"!=typeof navigator&&"string"==typeof navigator.userAgent?navigator.userAgent:""}function h(){return"undefined"!=typeof window&&!!(window.cordova||window.phonegap||window.PhoneGap)&&/ios|iphone|ipod|ipad|android|blackberry|iemobile/i.test(c())}function d(){try{return"[object process]"===Object.prototype.toString.call(n.g.process)}catch(e){return!1}}function f(){return"object"==typeof self&&self.self===self}function p(){let e="object"==typeof chrome?chrome.runtime:"object"==typeof browser?browser.runtime:void 0;return"object"==typeof e&&void 0!==e.id}function m(){return"object"==typeof navigator&&"ReactNative"===navigator.product}function g(){let e=c();return e.indexOf("MSIE ")>=0||e.indexOf("Trident/")>=0}function y(){return!d()&&navigator.userAgent.includes("Safari")&&!navigator.userAgent.includes("Chrome")}function v(){try{return"object"==typeof indexedDB}catch(e){return!1}}function w(){return new Promise((e,t)=>{try{let n=!0,r="validate-browser-context-for-indexeddb-analytics-module",i=self.indexedDB.open(r);i.onsuccess=()=>{i.result.close(),n||self.indexedDB.deleteDatabase(r),e(!0)},i.onupgradeneeded=()=>{n=!1},i.onerror=()=>{var e;t((null===(e=i.error)||void 0===e?void 0:e.message)||"")}}catch(s){t(s)}})}function _(){return"undefined"!=typeof navigator&&!!navigator.cookieEnabled}/**
 * @license
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let b=()=>(function(){if("undefined"!=typeof self)return self;if("undefined"!=typeof window)return window;if(void 0!==n.g)return n.g;throw Error("Unable to locate global object.")})().__FIREBASE_DEFAULTS__,I=()=>{if(void 0===r||void 0===r.env)return;let e=r.env.__FIREBASE_DEFAULTS__;if(e)return JSON.parse(e)},T=()=>{let e;if("undefined"==typeof document)return;try{e=document.cookie.match(/__FIREBASE_DEFAULTS__=([^;]+)/)}catch(t){return}let n=e&&u(e[1]);return n&&JSON.parse(n)},E=()=>{try{return b()||I()||T()}catch(e){console.info(`Unable to get __FIREBASE_DEFAULTS__ due to: ${e}`);return}},S=()=>{var e;return null===(e=E())||void 0===e?void 0:e.config},k=e=>{var t;return null===(t=E())||void 0===t?void 0:t[`_${e}`]};/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class A{constructor(){this.reject=()=>{},this.resolve=()=>{},this.promise=new Promise((e,t)=>{this.resolve=e,this.reject=t})}wrapCallback(e){return(t,n)=>{t?this.reject(t):this.resolve(n),"function"==typeof e&&(this.promise.catch(()=>{}),1===e.length?e(t):e(t,n))}}}/**
 * @license
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function C(e,t){if(e.uid)throw Error('The "uid" field is no longer supported by mockUserToken. Please use "sub" instead for Firebase Auth User ID.');let n=t||"demo-project",r=e.iat||0,i=e.sub||e.user_id;if(!i)throw Error("mockUserToken must contain 'sub' or 'user_id' field!");let s=Object.assign({iss:`https://securetoken.google.com/${n}`,aud:n,iat:r,exp:r+3600,auth_time:r,sub:i,user_id:i,firebase:{sign_in_provider:"custom",identities:{}}},e);return[l(JSON.stringify({alg:"none",type:"JWT"})),l(JSON.stringify(s)),""].join(".")}class x extends Error{constructor(e,t,n){super(t),this.code=e,this.customData=n,this.name="FirebaseError",Object.setPrototypeOf(this,x.prototype),Error.captureStackTrace&&Error.captureStackTrace(this,R.prototype.create)}}class R{constructor(e,t,n){this.service=e,this.serviceName=t,this.errors=n}create(e,...t){let n=t[0]||{},r=`${this.service}/${e}`,i=this.errors[e],s=i?i.replace(D,(e,t)=>{let r=n[t];return null!=r?String(r):`<${t}?>`}):"Error",a=`${this.serviceName}: ${s} (${r}).`,o=new x(r,a,n);return o}}let D=/\{\$([^}]+)}/g;/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function N(e,t){return Object.prototype.hasOwnProperty.call(e,t)}function O(e){for(let t in e)if(Object.prototype.hasOwnProperty.call(e,t))return!1;return!0}function P(e){return null!==e&&"object"==typeof e}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function L(e){let t=[];for(let[n,r]of Object.entries(e))Array.isArray(r)?r.forEach(e=>{t.push(encodeURIComponent(n)+"="+encodeURIComponent(e))}):t.push(encodeURIComponent(n)+"="+encodeURIComponent(r));return t.length?"&"+t.join("&"):""}function M(e){let t={},n=e.replace(/^\?/,"").split("&");return n.forEach(e=>{if(e){let[n,r]=e.split("=");t[decodeURIComponent(n)]=decodeURIComponent(r)}}),t}function F(e){let t=e.indexOf("?");if(!t)return"";let n=e.indexOf("#",t);return e.substring(t,n>0?n:void 0)}function U(e,t){let n=new V(e,t);return n.subscribe.bind(n)}class V{constructor(e,t){this.observers=[],this.unsubscribes=[],this.observerCount=0,this.task=Promise.resolve(),this.finalized=!1,this.onNoObservers=t,this.task.then(()=>{e(this)}).catch(e=>{this.error(e)})}next(e){this.forEachObserver(t=>{t.next(e)})}error(e){this.forEachObserver(t=>{t.error(e)}),this.close(e)}complete(){this.forEachObserver(e=>{e.complete()}),this.close()}subscribe(e,t,n){let r;if(void 0===e&&void 0===t&&void 0===n)throw Error("Missing Observer.");void 0===(r=!function(e,t){if("object"!=typeof e||null===e)return!1;for(let n of t)if(n in e&&"function"==typeof e[n])return!0;return!1}(e,["next","error","complete"])?{next:e,error:t,complete:n}:e).next&&(r.next=q),void 0===r.error&&(r.error=q),void 0===r.complete&&(r.complete=q);let i=this.unsubscribeOne.bind(this,this.observers.length);return this.finalized&&this.task.then(()=>{try{this.finalError?r.error(this.finalError):r.complete()}catch(e){}}),this.observers.push(r),i}unsubscribeOne(e){void 0!==this.observers&&void 0!==this.observers[e]&&(delete this.observers[e],this.observerCount-=1,0===this.observerCount&&void 0!==this.onNoObservers&&this.onNoObservers(this))}forEachObserver(e){if(!this.finalized)for(let t=0;t<this.observers.length;t++)this.sendOne(t,e)}sendOne(e,t){this.task.then(()=>{if(void 0!==this.observers&&void 0!==this.observers[e])try{t(this.observers[e])}catch(n){"undefined"!=typeof console&&console.error&&console.error(n)}})}close(e){this.finalized||(this.finalized=!0,void 0!==e&&(this.finalError=e),this.task.then(()=>{this.observers=void 0,this.onNoObservers=void 0}))}}function q(){}function B(e,t=1e3,n=2){let r=t*Math.pow(n,e);return Math.min(144e5,r+Math.round(.5*r*(Math.random()-.5)*2))}/**
 * @license
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function j(e){return e&&e._delegate?e._delegate:e}},3454:function(e,t,n){"use strict";var r,i;e.exports=(null==(r=n.g.process)?void 0:r.env)&&"object"==typeof(null==(i=n.g.process)?void 0:i.env)?n.g.process:n(7663)},1118:function(e,t,n){(window.__NEXT_P=window.__NEXT_P||[]).push(["/_app",function(){return n(2224)}])},8059:function(e,t,n){"use strict";n.d(t,{S:function(){return i}});var r=n(7294);let i=(0,r.createContext)({user:null,username:null})},26:function(e,t,n){"use strict";let r,i,s,a;n.d(t,{mC:function(){return nz},I8:function(){return nq},RZ:function(){return nj},Lg:function(){return nG},qV:function(){return nB},nP:function(){return nH},Bt:function(){return nK},tO:function(){return n$}});var o,l,u=n(4444),c=n(8463),h=n(2238),d=n(3333);/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class f{constructor(e,t){this._delegate=e,this.firebase=t,(0,h._addComponent)(e,new c.wA("app-compat",()=>this,"PUBLIC")),this.container=e.container}get automaticDataCollectionEnabled(){return this._delegate.automaticDataCollectionEnabled}set automaticDataCollectionEnabled(e){this._delegate.automaticDataCollectionEnabled=e}get name(){return this._delegate.name}get options(){return this._delegate.options}delete(){return new Promise(e=>{this._delegate.checkDestroyed(),e()}).then(()=>(this.firebase.INTERNAL.removeApp(this.name),(0,h.deleteApp)(this._delegate)))}_getService(e,t=h._DEFAULT_ENTRY_NAME){var n;this._delegate.checkDestroyed();let r=this._delegate.container.getProvider(e);return r.isInitialized()||(null===(n=r.getComponent())||void 0===n?void 0:n.instantiationMode)!=="EXPLICIT"||r.initialize(),r.getImmediate({identifier:t})}_removeServiceInstance(e,t=h._DEFAULT_ENTRY_NAME){this._delegate.container.getProvider(e).clearInstance(t)}_addComponent(e){(0,h._addComponent)(this._delegate,e)}_addOrOverwriteComponent(e){(0,h._addOrOverwriteComponent)(this._delegate,e)}toJSON(){return{name:this.name,automaticDataCollectionEnabled:this.automaticDataCollectionEnabled,options:this.options}}}let p=new u.LL("app-compat","Firebase",{"no-app":"No Firebase App '{$appName}' has been created - call Firebase App.initializeApp()","invalid-app-argument":"firebase.{$appName}() takes either no argument or a Firebase App instance."}),m=/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function e(){let t=/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function(e){let t={},n={__esModule:!0,initializeApp:function(r,i={}){let s=h.initializeApp(r,i);if((0,u.r3)(t,s.name))return t[s.name];let a=new e(s,n);return t[s.name]=a,a},app:r,registerVersion:h.registerVersion,setLogLevel:h.setLogLevel,onLog:h.onLog,apps:null,SDK_VERSION:h.SDK_VERSION,INTERNAL:{registerComponent:function(t){let i=t.name,s=i.replace("-compat","");if(h._registerComponent(t)&&"PUBLIC"===t.type){let a=(e=r())=>{if("function"!=typeof e[s])throw p.create("invalid-app-argument",{appName:i});return e[s]()};void 0!==t.serviceProps&&(0,u.ZB)(a,t.serviceProps),n[s]=a,e.prototype[s]=function(...e){let n=this._getService.bind(this,i);return n.apply(this,t.multipleInstances?e:[])}}return"PUBLIC"===t.type?n[s]:null},removeApp:function(e){delete t[e]},useAsService:function(e,t){return"serverAuth"===t?null:t},modularAPIs:h}};function r(e){if(e=e||h._DEFAULT_ENTRY_NAME,!(0,u.r3)(t,e))throw p.create("no-app",{appName:e});return t[e]}return n.default=n,Object.defineProperty(n,"apps",{get:function(){return Object.keys(t).map(e=>t[e])}}),r.App=e,n}(f);return t.INTERNAL=Object.assign(Object.assign({},t.INTERNAL),{createFirebaseNamespace:e,extendNamespace:function(e){(0,u.ZB)(t,e)},createSubscribe:u.ne,ErrorFactory:u.LL,deepExtend:u.ZB}),t}(),g=new d.Yd("@firebase/app-compat");/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */if((0,u.jU)()&&void 0!==self.firebase){g.warn(`
    Warning: Firebase is already defined in the global scope. Please make sure
    Firebase library is only loaded once.
  `);let y=self.firebase.SDK_VERSION;y&&y.indexOf("LITE")>=0&&g.warn(`
    Warning: You are trying to load Firebase while using Firebase Performance standalone script.
    You should load Firebase Performance with this instance of Firebase to avoid loading duplicate code.
    `)}(0,h.registerVersion)("@firebase/app-compat","0.2.0",void 0),/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */m.registerVersion("firebase","9.15.0","app-compat");var v=n(5786);/**
 * @license
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function w(){return window}async function _(e,t,n){var r;let{BuildInfo:i}=w();(0,v.ap)(t.sessionId,"AuthEvent did not contain a session ID");let s=await T(t.sessionId),a={};return(0,v.aq)()?a.ibi=i.packageName:(0,v.ar)()?a.apn=i.packageName:(0,v.as)(e,"operation-not-supported-in-this-environment"),i.displayName&&(a.appDisplayName=i.displayName),a.sessionId=s,(0,v.at)(e,n,t.type,void 0,null!==(r=t.eventId)&&void 0!==r?r:void 0,a)}async function b(e){let{BuildInfo:t}=w(),n={};(0,v.aq)()?n.iosBundleId=t.packageName:(0,v.ar)()?n.androidPackageName=t.packageName:(0,v.as)(e,"operation-not-supported-in-this-environment"),await (0,v.au)(e,n)}async function I(e,t,n){let{cordova:r}=w(),i=()=>{};try{await new Promise((s,a)=>{let o=null;function l(){var e;s();let t=null===(e=r.plugins.browsertab)||void 0===e?void 0:e.close;"function"==typeof t&&t(),"function"==typeof(null==n?void 0:n.close)&&n.close()}function u(){o||(o=window.setTimeout(()=>{a((0,v.aw)(e,"redirect-cancelled-by-user"))},2e3))}function c(){(null==document?void 0:document.visibilityState)==="visible"&&u()}t.addPassiveListener(l),document.addEventListener("resume",u,!1),(0,v.ar)()&&document.addEventListener("visibilitychange",c,!1),i=()=>{t.removePassiveListener(l),document.removeEventListener("resume",u,!1),document.removeEventListener("visibilitychange",c,!1),o&&window.clearTimeout(o)}})}finally{i()}}async function T(e){let t=function(e){if((0,v.ap)(/[0-9a-zA-Z]+/.test(e),"Can only convert alpha-numeric strings"),"undefined"!=typeof TextEncoder)return new TextEncoder().encode(e);let t=new ArrayBuffer(e.length),n=new Uint8Array(t);for(let r=0;r<e.length;r++)n[r]=e.charCodeAt(r);return n}(e),n=await crypto.subtle.digest("SHA-256",t),r=Array.from(new Uint8Array(n));return r.map(e=>e.toString(16).padStart(2,"0")).join("")}class E extends v.ay{constructor(){super(...arguments),this.passiveListeners=new Set,this.initPromise=new Promise(e=>{this.resolveInialized=e})}addPassiveListener(e){this.passiveListeners.add(e)}removePassiveListener(e){this.passiveListeners.delete(e)}resetRedirect(){this.queuedRedirectEvent=null,this.hasHandledPotentialRedirect=!1}onEvent(e){return this.resolveInialized(),this.passiveListeners.forEach(t=>t(e)),super.onEvent(e)}async initialized(){await this.initPromise}}async function S(e){let t=await k()._get(A(e));return t&&await k()._remove(A(e)),t}function k(){return(0,v.az)(v.b)}function A(e){return(0,v.aA)("authEvent",e.config.apiKey,e.name)}function C(e){if(!(null==e?void 0:e.includes("?")))return{};let[t,...n]=e.split("?");return(0,u.zd)(n.join("?"))}let x=class{constructor(){this._redirectPersistence=v.a,this._shouldInitProactively=!0,this.eventManagers=new Map,this.originValidationPromises={},this._completeRedirectFn=v.aB,this._overrideRedirectResult=v.aC}async _initialize(e){let t=e._key(),n=this.eventManagers.get(t);return n||(n=new E(e),this.eventManagers.set(t,n),this.attachCallbackListeners(e,n)),n}_openPopup(e){(0,v.as)(e,"operation-not-supported-in-this-environment")}async _openRedirect(e,t,n,r){!function(e){var t,n,r,i,s,a,o,l,u,c;let h=w();(0,v.ax)("function"==typeof(null===(t=null==h?void 0:h.universalLinks)||void 0===t?void 0:t.subscribe),e,"invalid-cordova-configuration",{missingPlugin:"cordova-universal-links-plugin-fix"}),(0,v.ax)(void 0!==(null===(n=null==h?void 0:h.BuildInfo)||void 0===n?void 0:n.packageName),e,"invalid-cordova-configuration",{missingPlugin:"cordova-plugin-buildInfo"}),(0,v.ax)("function"==typeof(null===(s=null===(i=null===(r=null==h?void 0:h.cordova)||void 0===r?void 0:r.plugins)||void 0===i?void 0:i.browsertab)||void 0===s?void 0:s.openUrl),e,"invalid-cordova-configuration",{missingPlugin:"cordova-plugin-browsertab"}),(0,v.ax)("function"==typeof(null===(l=null===(o=null===(a=null==h?void 0:h.cordova)||void 0===a?void 0:a.plugins)||void 0===o?void 0:o.browsertab)||void 0===l?void 0:l.isAvailable),e,"invalid-cordova-configuration",{missingPlugin:"cordova-plugin-browsertab"}),(0,v.ax)("function"==typeof(null===(c=null===(u=null==h?void 0:h.cordova)||void 0===u?void 0:u.InAppBrowser)||void 0===c?void 0:c.open),e,"invalid-cordova-configuration",{missingPlugin:"cordova-plugin-inappbrowser"})}(e);let i=await this._initialize(e);await i.initialized(),i.resetRedirect(),(0,v.aD)(),await this._originValidation(e);let s=function(e,t,n=null){return{type:t,eventId:n,urlResponse:null,sessionId:function(){let e=[],t="1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";for(let n=0;n<20;n++){let r=Math.floor(Math.random()*t.length);e.push(t.charAt(r))}return e.join("")}(),postBody:null,tenantId:e.tenantId,error:(0,v.aw)(e,"no-auth-event")}}(e,n,r);await k()._set(A(e),s);let a=await _(e,s,t),o=await function(e){let{cordova:t}=w();return new Promise(n=>{t.plugins.browsertab.isAvailable(r=>{let i=null;r?t.plugins.browsertab.openUrl(e):i=t.InAppBrowser.open(e,(0,v.av)()?"_blank":"_system","location=yes"),n(i)})})}(a);return I(e,i,o)}_isIframeWebStorageSupported(e,t){throw Error("Method not implemented.")}_originValidation(e){let t=e._key();return this.originValidationPromises[t]||(this.originValidationPromises[t]=b(e)),this.originValidationPromises[t]}attachCallbackListeners(e,t){let{universalLinks:n,handleOpenURL:r,BuildInfo:i}=w(),s=setTimeout(async()=>{await S(e),t.onEvent(R())},500),a=async n=>{clearTimeout(s);let r=await S(e),i=null;r&&(null==n?void 0:n.url)&&(i=function(e,t){var n,r;let i=function(e){let t=C(e),n=t.link?decodeURIComponent(t.link):void 0,r=C(n).link,i=t.deep_link_id?decodeURIComponent(t.deep_link_id):void 0,s=C(i).link;return s||i||r||n||e}(t);if(i.includes("/__/auth/callback")){let s=C(i),a=s.firebaseError?function(e){try{return JSON.parse(e)}catch(t){return null}}(decodeURIComponent(s.firebaseError)):null,o=null===(r=null===(n=null==a?void 0:a.code)||void 0===n?void 0:n.split("auth/"))||void 0===r?void 0:r[1],l=o?(0,v.aw)(o):null;return l?{type:e.type,eventId:e.eventId,tenantId:e.tenantId,error:l,urlResponse:null,sessionId:null,postBody:null}:{type:e.type,eventId:e.eventId,tenantId:e.tenantId,sessionId:e.sessionId,urlResponse:i,postBody:null}}return null}(r,n.url)),t.onEvent(i||R())};void 0!==n&&"function"==typeof n.subscribe&&n.subscribe(null,a);let o=`${i.packageName.toLowerCase()}://`;w().handleOpenURL=async e=>{if(e.toLowerCase().startsWith(o)&&a({url:e}),"function"==typeof r)try{r(e)}catch(t){console.error(t)}}}};function R(){return{type:"unknown",eventId:null,sessionId:null,urlResponse:null,postBody:null,tenantId:null,error:(0,v.aw)("no-auth-event")}}function D(){var e;return(null===(e=null==self?void 0:self.location)||void 0===e?void 0:e.protocol)||null}function N(e=(0,u.z$)()){return!!(("file:"===D()||"ionic:"===D()||"capacitor:"===D())&&e.toLowerCase().match(/iphone|ipad|ipod|android/))}function O(){try{let e=self.localStorage,t=v.aI();if(e){if(e.setItem(t,"1"),e.removeItem(t),function(e=(0,u.z$)()){return(0,u.w1)()&&(null==document?void 0:document.documentMode)===11||function(e=(0,u.z$)()){return/Edge\/\d+/.test(e)}(e)}())return(0,u.hl)();return!0}}catch(n){return P()&&(0,u.hl)()}return!1}function P(){return void 0!==n.g&&"WorkerGlobalScope"in n.g&&"importScripts"in n.g}function L(){return("http:"===D()||"https:"===D()||(0,u.ru)()||N())&&!((0,u.b$)()||(0,u.UG)())&&O()&&!P()}function M(){return N()&&"undefined"!=typeof document}async function F(){return!!M()&&new Promise(e=>{let t=setTimeout(()=>{e(!1)},1e3);document.addEventListener("deviceready",()=>{clearTimeout(t),e(!0)})})}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let U={LOCAL:"local",NONE:"none",SESSION:"session"},V=v.ax,q="persistence";async function B(e){await e._initializationPromise;let t=j(),n=v.aA(q,e.config.apiKey,e.name);t&&t.setItem(n,e._getPersistence())}function j(){var e;try{return(null===(e="undefined"!=typeof window?window:null)||void 0===e?void 0:e.sessionStorage)||null}catch(t){return null}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let $=v.ax;class z{constructor(){this.browserResolver=v.az(v.k),this.cordovaResolver=v.az(x),this.underlyingResolver=null,this._redirectPersistence=v.a,this._completeRedirectFn=v.aB,this._overrideRedirectResult=v.aC}async _initialize(e){return await this.selectUnderlyingResolver(),this.assertedUnderlyingResolver._initialize(e)}async _openPopup(e,t,n,r){return await this.selectUnderlyingResolver(),this.assertedUnderlyingResolver._openPopup(e,t,n,r)}async _openRedirect(e,t,n,r){return await this.selectUnderlyingResolver(),this.assertedUnderlyingResolver._openRedirect(e,t,n,r)}_isIframeWebStorageSupported(e,t){this.assertedUnderlyingResolver._isIframeWebStorageSupported(e,t)}_originValidation(e){return this.assertedUnderlyingResolver._originValidation(e)}get _shouldInitProactively(){return M()||this.browserResolver._shouldInitProactively}get assertedUnderlyingResolver(){return $(this.underlyingResolver,"internal-error"),this.underlyingResolver}async selectUnderlyingResolver(){if(this.underlyingResolver)return;let e=await F();this.underlyingResolver=e?this.cordovaResolver:this.browserResolver}}function G(e){let t;let{_tokenResponse:n}=e instanceof u.ZR?e.customData:e;if(!n)return null;if(!(e instanceof u.ZR)&&"temporaryProof"in n&&"phoneNumber"in n)return v.P.credentialFromResult(e);let r=n.providerId;if(!r||r===v.o.PASSWORD)return null;switch(r){case v.o.GOOGLE:t=v.Q;break;case v.o.FACEBOOK:t=v.N;break;case v.o.GITHUB:t=v.T;break;case v.o.TWITTER:t=v.W;break;default:let{oauthIdToken:i,oauthAccessToken:s,oauthTokenSecret:a,pendingToken:o,nonce:l}=n;if(!s&&!a&&!i&&!o)return null;if(o){if(r.startsWith("saml."))return v.aL._create(r,o);return v.J._fromParams({providerId:r,signInMethod:r,pendingToken:o,idToken:i,accessToken:s})}return new v.U(r).credential({idToken:i,accessToken:s,rawNonce:l})}return e instanceof u.ZR?t.credentialFromError(e):t.credentialFromResult(e)}function K(e,t){return t.catch(t=>{throw t instanceof u.ZR&&function(e,t){var n;let r=null===(n=t.customData)||void 0===n?void 0:n._tokenResponse;if((null==t?void 0:t.code)==="auth/multi-factor-auth-required"){let i=t;i.resolver=new W(e,v.an(e,t))}else if(r){let s=G(t),a=t;s&&(a.credential=s,a.tenantId=r.tenantId||void 0,a.email=r.email||void 0,a.phoneNumber=r.phoneNumber||void 0)}}(e,t),t}).then(e=>{let t=e.operationType,n=e.user;return{operationType:t,credential:G(e),additionalUserInfo:v.al(e),user:Q.getOrCreate(n)}})}async function H(e,t){let n=await t;return{verificationId:n.verificationId,confirm:t=>K(e,n.confirm(t))}}class W{constructor(e,t){this.resolver=t,this.auth=e.wrapped()}get session(){return this.resolver.session}get hints(){return this.resolver.hints}resolveSignIn(e){return K(this.auth.unwrap(),this.resolver.resolveSignIn(e))}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class Q{constructor(e){this._delegate=e,this.multiFactor=v.ao(e)}static getOrCreate(e){return Q.USER_MAP.has(e)||Q.USER_MAP.set(e,new Q(e)),Q.USER_MAP.get(e)}delete(){return this._delegate.delete()}reload(){return this._delegate.reload()}toJSON(){return this._delegate.toJSON()}getIdTokenResult(e){return this._delegate.getIdTokenResult(e)}getIdToken(e){return this._delegate.getIdToken(e)}linkAndRetrieveDataWithCredential(e){return this.linkWithCredential(e)}async linkWithCredential(e){return K(this.auth,v.Z(this._delegate,e))}async linkWithPhoneNumber(e,t){return H(this.auth,v.l(this._delegate,e,t))}async linkWithPopup(e){return K(this.auth,v.d(this._delegate,e,z))}async linkWithRedirect(e){return await B(v.aE(this.auth)),v.g(this._delegate,e,z)}reauthenticateAndRetrieveDataWithCredential(e){return this.reauthenticateWithCredential(e)}async reauthenticateWithCredential(e){return K(this.auth,v._(this._delegate,e))}reauthenticateWithPhoneNumber(e,t){return H(this.auth,v.r(this._delegate,e,t))}reauthenticateWithPopup(e){return K(this.auth,v.e(this._delegate,e,z))}async reauthenticateWithRedirect(e){return await B(v.aE(this.auth)),v.h(this._delegate,e,z)}sendEmailVerification(e){return v.ab(this._delegate,e)}async unlink(e){return await v.ak(this._delegate,e),this}updateEmail(e){return v.ag(this._delegate,e)}updatePassword(e){return v.ah(this._delegate,e)}updatePhoneNumber(e){return v.u(this._delegate,e)}updateProfile(e){return v.af(this._delegate,e)}verifyBeforeUpdateEmail(e,t){return v.ac(this._delegate,e,t)}get emailVerified(){return this._delegate.emailVerified}get isAnonymous(){return this._delegate.isAnonymous}get metadata(){return this._delegate.metadata}get phoneNumber(){return this._delegate.phoneNumber}get providerData(){return this._delegate.providerData}get refreshToken(){return this._delegate.refreshToken}get tenantId(){return this._delegate.tenantId}get displayName(){return this._delegate.displayName}get email(){return this._delegate.email}get photoURL(){return this._delegate.photoURL}get providerId(){return this._delegate.providerId}get uid(){return this._delegate.uid}get auth(){return this._delegate.auth}}Q.USER_MAP=new WeakMap;/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let Y=v.ax;class X{constructor(e,t){if(this.app=e,t.isInitialized()){this._delegate=t.getImmediate(),this.linkUnderlyingAuth();return}let{apiKey:n}=e.options;Y(n,"invalid-api-key",{appName:e.name}),Y(n,"invalid-api-key",{appName:e.name});let r="undefined"!=typeof window?z:void 0;this._delegate=t.initialize({options:{persistence:function(e,t){let n=function(e,t){let n=j();if(!n)return[];let r=v.aA(q,e,t),i=n.getItem(r);switch(i){case U.NONE:return[v.L];case U.LOCAL:return[v.i,v.a];case U.SESSION:return[v.a];default:return[]}}(e,t);if("undefined"==typeof self||n.includes(v.i)||n.push(v.i),"undefined"!=typeof window)for(let r of[v.b,v.a])n.includes(r)||n.push(r);return n.includes(v.L)||n.push(v.L),n}(n,e.name),popupRedirectResolver:r}}),this._delegate._updateErrorMap(v.B),this.linkUnderlyingAuth()}get emulatorConfig(){return this._delegate.emulatorConfig}get currentUser(){return this._delegate.currentUser?Q.getOrCreate(this._delegate.currentUser):null}get languageCode(){return this._delegate.languageCode}set languageCode(e){this._delegate.languageCode=e}get settings(){return this._delegate.settings}get tenantId(){return this._delegate.tenantId}set tenantId(e){this._delegate.tenantId=e}useDeviceLanguage(){this._delegate.useDeviceLanguage()}signOut(){return this._delegate.signOut()}useEmulator(e,t){v.G(this._delegate,e,t)}applyActionCode(e){return v.a2(this._delegate,e)}checkActionCode(e){return v.a3(this._delegate,e)}confirmPasswordReset(e,t){return v.a1(this._delegate,e,t)}async createUserWithEmailAndPassword(e,t){return K(this._delegate,v.a5(this._delegate,e,t))}fetchProvidersForEmail(e){return this.fetchSignInMethodsForEmail(e)}fetchSignInMethodsForEmail(e){return v.aa(this._delegate,e)}isSignInWithEmailLink(e){return v.a8(this._delegate,e)}async getRedirectResult(){Y(L(),this._delegate,"operation-not-supported-in-this-environment");let e=await v.j(this._delegate,z);return e?K(this._delegate,Promise.resolve(e)):{credential:null,user:null}}addFrameworkForLogging(e){!/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function(e,t){(0,v.aE)(e)._logFramework(t)}(this._delegate,e)}onAuthStateChanged(e,t,n){let{next:r,error:i,complete:s}=J(e,t,n);return this._delegate.onAuthStateChanged(r,i,s)}onIdTokenChanged(e,t,n){let{next:r,error:i,complete:s}=J(e,t,n);return this._delegate.onIdTokenChanged(r,i,s)}sendSignInLinkToEmail(e,t){return v.a7(this._delegate,e,t)}sendPasswordResetEmail(e,t){return v.a0(this._delegate,e,t||void 0)}async setPersistence(e){let t;switch(!function(e,t){if(V(Object.values(U).includes(t),e,"invalid-persistence-type"),(0,u.b$)()){V(t!==U.SESSION,e,"unsupported-persistence-type");return}if((0,u.UG)()){V(t===U.NONE,e,"unsupported-persistence-type");return}if(P()){V(t===U.NONE||t===U.LOCAL&&(0,u.hl)(),e,"unsupported-persistence-type");return}V(t===U.NONE||O(),e,"unsupported-persistence-type")}(this._delegate,e),e){case U.SESSION:t=v.a;break;case U.LOCAL:let n=await v.az(v.i)._isAvailable();t=n?v.i:v.b;break;case U.NONE:t=v.L;break;default:return v.as("argument-error",{appName:this._delegate.name})}return this._delegate.setPersistence(t)}signInAndRetrieveDataWithCredential(e){return this.signInWithCredential(e)}signInAnonymously(){return K(this._delegate,v.X(this._delegate))}signInWithCredential(e){return K(this._delegate,v.Y(this._delegate,e))}signInWithCustomToken(e){return K(this._delegate,v.$(this._delegate,e))}signInWithEmailAndPassword(e,t){return K(this._delegate,v.a6(this._delegate,e,t))}signInWithEmailLink(e,t){return K(this._delegate,v.a9(this._delegate,e,t))}signInWithPhoneNumber(e,t){return H(this._delegate,v.s(this._delegate,e,t))}async signInWithPopup(e){return Y(L(),this._delegate,"operation-not-supported-in-this-environment"),K(this._delegate,v.c(this._delegate,e,z))}async signInWithRedirect(e){return Y(L(),this._delegate,"operation-not-supported-in-this-environment"),await B(this._delegate),v.f(this._delegate,e,z)}updateCurrentUser(e){return this._delegate.updateCurrentUser(e)}verifyPasswordResetCode(e){return v.a4(this._delegate,e)}unwrap(){return this._delegate}_delete(){return this._delegate._delete()}linkUnderlyingAuth(){this._delegate.wrapped=()=>this}}function J(e,t,n){let r=e;"function"!=typeof e&&({next:r,error:t,complete:n}=e);let i=r,s=e=>i(e&&Q.getOrCreate(e));return{next:s,error:t,complete:n}}X.Persistence=U;/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class Z{constructor(){this.providerId="phone",this._delegate=new v.P(m.auth().unwrap())}static credential(e,t){return v.P.credential(e,t)}verifyPhoneNumber(e,t){return this._delegate.verifyPhoneNumber(e,t)}unwrap(){return this._delegate}}Z.PHONE_SIGN_IN_METHOD=v.P.PHONE_SIGN_IN_METHOD,Z.PROVIDER_ID=v.P.PROVIDER_ID;/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let ee=v.ax;m.INTERNAL.registerComponent(new c.wA("auth-compat",e=>{let t=e.getProvider("app-compat").getImmediate(),n=e.getProvider("auth");return new X(t,n)},"PUBLIC").setServiceProps({ActionCodeInfo:{Operation:{EMAIL_SIGNIN:v.A.EMAIL_SIGNIN,PASSWORD_RESET:v.A.PASSWORD_RESET,RECOVER_EMAIL:v.A.RECOVER_EMAIL,REVERT_SECOND_FACTOR_ADDITION:v.A.REVERT_SECOND_FACTOR_ADDITION,VERIFY_AND_CHANGE_EMAIL:v.A.VERIFY_AND_CHANGE_EMAIL,VERIFY_EMAIL:v.A.VERIFY_EMAIL}},EmailAuthProvider:v.M,FacebookAuthProvider:v.N,GithubAuthProvider:v.T,GoogleAuthProvider:v.Q,OAuthProvider:v.U,SAMLAuthProvider:v.V,PhoneAuthProvider:Z,PhoneMultiFactorGenerator:v.m,RecaptchaVerifier:class{constructor(e,t,n=m.app()){var r;ee(null===(r=n.options)||void 0===r?void 0:r.apiKey,"invalid-api-key",{appName:n.name}),this._delegate=new v.R(e,t,n.auth()),this.type=this._delegate.type}clear(){this._delegate.clear()}render(){return this._delegate.render()}verify(){return this._delegate.verify()}},TwitterAuthProvider:v.W,Auth:X,AuthCredential:v.H,Error:u.ZR}).setInstantiationMode("LAZY").setMultipleInstances(!1)),m.registerVersion("@firebase/auth-compat","0.3.0");var et=n(1294);/**
 * @license
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function en(e,t){if(void 0===t)return{merge:!1};if(void 0!==t.mergeFields&&void 0!==t.merge)throw new et.WA("invalid-argument",`Invalid options passed to function ${e}(): You cannot specify both "merge" and "mergeFields".`);return t}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function er(){if("undefined"==typeof Uint8Array)throw new et.WA("unimplemented","Uint8Arrays are not available in this environment.")}function ei(){if(!(0,et.Me)())throw new et.WA("unimplemented","Blobs are unavailable in Firestore in this environment.")}class es{constructor(e){this._delegate=e}static fromBase64String(e){return ei(),new es(et.Jj.fromBase64String(e))}static fromUint8Array(e){return er(),new es(et.Jj.fromUint8Array(e))}toBase64(){return ei(),this._delegate.toBase64()}toUint8Array(){return er(),this._delegate.toUint8Array()}isEqual(e){return this._delegate.isEqual(e._delegate)}toString(){return"Blob(base64: "+this.toBase64()+")"}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function ea(e){return function(e,t){if("object"!=typeof e||null===e)return!1;for(let n of t)if(n in e&&"function"==typeof e[n])return!0;return!1}(e,["next","error","complete"])}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class eo{enableIndexedDbPersistence(e,t){return(0,et.ST)(e._delegate,{forceOwnership:t})}enableMultiTabIndexedDbPersistence(e){return(0,et.fH)(e._delegate)}clearIndexedDbPersistence(e){return(0,et.Fc)(e._delegate)}}class el{constructor(e,t,n){this._delegate=t,this._persistenceProvider=n,this.INTERNAL={delete:()=>this.terminate()},e instanceof et.l7||(this._appCompat=e)}get _databaseId(){return this._delegate._databaseId}settings(e){let t=this._delegate._getSettings();e.merge||t.host===e.host||(0,et.yq)("You are overriding the original host. If you did not intend to override your settings, use {merge: true}."),e.merge&&delete(e=Object.assign(Object.assign({},t),e)).merge,this._delegate._setSettings(e)}useEmulator(e,t,n={}){(0,et.at)(this._delegate,e,t,n)}enableNetwork(){return(0,et.Ix)(this._delegate)}disableNetwork(){return(0,et.TF)(this._delegate)}enablePersistence(e){let t=!1,n=!1;return e&&(t=!!e.synchronizeTabs,n=!!e.experimentalForceOwningTab,(0,et.Wi)("synchronizeTabs",t,"experimentalForceOwningTab",n)),t?this._persistenceProvider.enableMultiTabIndexedDbPersistence(this):this._persistenceProvider.enableIndexedDbPersistence(this,n)}clearPersistence(){return this._persistenceProvider.clearIndexedDbPersistence(this)}terminate(){return this._appCompat&&(this._appCompat._removeServiceInstance("firestore-compat"),this._appCompat._removeServiceInstance("firestore")),this._delegate._delete()}waitForPendingWrites(){return(0,et.Mx)(this._delegate)}onSnapshotsInSync(e){return(0,et.sc)(this._delegate,e)}get app(){if(!this._appCompat)throw new et.WA("failed-precondition","Firestore was not initialized using the Firebase SDK. 'app' is not available");return this._appCompat}collection(e){try{return new eI(this,(0,et.hJ)(this._delegate,e))}catch(t){throw ep(t,"collection()","Firestore.collection()")}}doc(e){try{return new ef(this,(0,et.JU)(this._delegate,e))}catch(t){throw ep(t,"doc()","Firestore.doc()")}}collectionGroup(e){try{return new ew(this,(0,et.B$)(this._delegate,e))}catch(t){throw ep(t,"collectionGroup()","Firestore.collectionGroup()")}}runTransaction(e){return(0,et.i3)(this._delegate,t=>e(new ec(this,t)))}batch(){return(0,et.qY)(this._delegate),new eh(new et.PU(this._delegate,e=>(0,et.GL)(this._delegate,e)))}loadBundle(e){return(0,et.Pb)(this._delegate,e)}namedQuery(e){return(0,et.L$)(this._delegate,e).then(e=>e?new ew(this,e):null)}}class eu extends et.u7{constructor(e){super(),this.firestore=e}convertBytes(e){return new es(new et.Jj(e))}convertReference(e){let t=this.convertDocumentKey(e,this.firestore._databaseId);return ef.forKey(t,this.firestore,null)}}class ec{constructor(e,t){this._firestore=e,this._delegate=t,this._userDataWriter=new eu(e)}get(e){let t=eT(e);return this._delegate.get(t).then(e=>new ey(this._firestore,new et.xU(this._firestore._delegate,this._userDataWriter,e._key,e._document,e.metadata,t.converter)))}set(e,t,n){let r=eT(e);return n?(en("Transaction.set",n),this._delegate.set(r,t,n)):this._delegate.set(r,t),this}update(e,t,n,...r){let i=eT(e);return 2==arguments.length?this._delegate.update(i,t):this._delegate.update(i,t,n,...r),this}delete(e){let t=eT(e);return this._delegate.delete(t),this}}class eh{constructor(e){this._delegate=e}set(e,t,n){let r=eT(e);return n?(en("WriteBatch.set",n),this._delegate.set(r,t,n)):this._delegate.set(r,t),this}update(e,t,n,...r){let i=eT(e);return 2==arguments.length?this._delegate.update(i,t):this._delegate.update(i,t,n,...r),this}delete(e){let t=eT(e);return this._delegate.delete(t),this}commit(){return this._delegate.commit()}}class ed{constructor(e,t,n){this._firestore=e,this._userDataWriter=t,this._delegate=n}fromFirestore(e,t){let n=new et.$q(this._firestore._delegate,this._userDataWriter,e._key,e._document,e.metadata,null);return this._delegate.fromFirestore(new ev(this._firestore,n),null!=t?t:{})}toFirestore(e,t){return t?this._delegate.toFirestore(e,t):this._delegate.toFirestore(e)}static getInstance(e,t){let n=ed.INSTANCES,r=n.get(e);r||(r=new WeakMap,n.set(e,r));let i=r.get(t);return i||(i=new ed(e,new eu(e),t),r.set(t,i)),i}}ed.INSTANCES=new WeakMap;class ef{constructor(e,t){this.firestore=e,this._delegate=t,this._userDataWriter=new eu(e)}static forPath(e,t,n){if(e.length%2!=0)throw new et.WA("invalid-argument",`Invalid document reference. Document references must have an even number of segments, but ${e.canonicalString()} has ${e.length}`);return new ef(t,new et.my(t._delegate,n,new et.Ky(e)))}static forKey(e,t,n){return new ef(t,new et.my(t._delegate,n,e))}get id(){return this._delegate.id}get parent(){return new eI(this.firestore,this._delegate.parent)}get path(){return this._delegate.path}collection(e){try{return new eI(this.firestore,(0,et.hJ)(this._delegate,e))}catch(t){throw ep(t,"collection()","DocumentReference.collection()")}}isEqual(e){return(e=(0,u.m9)(e))instanceof et.my&&(0,et.Eo)(this._delegate,e)}set(e,t){t=en("DocumentReference.set",t);try{if(t)return(0,et.pl)(this._delegate,e,t);return(0,et.pl)(this._delegate,e)}catch(n){throw ep(n,"setDoc()","DocumentReference.set()")}}update(e,t,...n){try{if(1==arguments.length)return(0,et.r7)(this._delegate,e);return(0,et.r7)(this._delegate,e,t,...n)}catch(r){throw ep(r,"updateDoc()","DocumentReference.update()")}}delete(){return(0,et.oe)(this._delegate)}onSnapshot(...e){let t=em(e),n=eg(e,e=>new ey(this.firestore,new et.xU(this.firestore._delegate,this._userDataWriter,e._key,e._document,e.metadata,this._delegate.converter)));return(0,et.cf)(this._delegate,t,n)}get(e){return((null==e?void 0:e.source)==="cache"?(0,et.kl)(this._delegate):(null==e?void 0:e.source)==="server"?(0,et.Xk)(this._delegate):(0,et.QT)(this._delegate)).then(e=>new ey(this.firestore,new et.xU(this.firestore._delegate,this._userDataWriter,e._key,e._document,e.metadata,this._delegate.converter)))}withConverter(e){return new ef(this.firestore,e?this._delegate.withConverter(ed.getInstance(this.firestore,e)):this._delegate.withConverter(null))}}function ep(e,t,n){return e.message=e.message.replace(t,n),e}function em(e){for(let t of e)if("object"==typeof t&&!ea(t))return t;return{}}function eg(e,t){var n,r;let i;return{next:e=>{i.next&&i.next(t(e))},error:null===(n=(i=ea(e[0])?e[0]:ea(e[1])?e[1]:"function"==typeof e[0]?{next:e[0],error:e[1],complete:e[2]}:{next:e[1],error:e[2],complete:e[3]}).error)||void 0===n?void 0:n.bind(i),complete:null===(r=i.complete)||void 0===r?void 0:r.bind(i)}}class ey{constructor(e,t){this._firestore=e,this._delegate=t}get ref(){return new ef(this._firestore,this._delegate.ref)}get id(){return this._delegate.id}get metadata(){return this._delegate.metadata}get exists(){return this._delegate.exists()}data(e){return this._delegate.data(e)}get(e,t){return this._delegate.get(e,t)}isEqual(e){return(0,et.qK)(this._delegate,e._delegate)}}class ev extends ey{data(e){let t=this._delegate.data(e);return(0,et.K9)(void 0!==t,"Document in a QueryDocumentSnapshot should exist"),t}}class ew{constructor(e,t){this.firestore=e,this._delegate=t,this._userDataWriter=new eu(e)}where(e,t,n){try{return new ew(this.firestore,(0,et.IO)(this._delegate,(0,et.ar)(e,t,n)))}catch(r){throw ep(r,/(orderBy|where)\(\)/,"Query.$1()")}}orderBy(e,t){try{return new ew(this.firestore,(0,et.IO)(this._delegate,(0,et.Xo)(e,t)))}catch(n){throw ep(n,/(orderBy|where)\(\)/,"Query.$1()")}}limit(e){try{return new ew(this.firestore,(0,et.IO)(this._delegate,(0,et.b9)(e)))}catch(t){throw ep(t,"limit()","Query.limit()")}}limitToLast(e){try{return new ew(this.firestore,(0,et.IO)(this._delegate,(0,et.vh)(e)))}catch(t){throw ep(t,"limitToLast()","Query.limitToLast()")}}startAt(...e){try{return new ew(this.firestore,(0,et.IO)(this._delegate,(0,et.e0)(...e)))}catch(t){throw ep(t,"startAt()","Query.startAt()")}}startAfter(...e){try{return new ew(this.firestore,(0,et.IO)(this._delegate,(0,et.TQ)(...e)))}catch(t){throw ep(t,"startAfter()","Query.startAfter()")}}endBefore(...e){try{return new ew(this.firestore,(0,et.IO)(this._delegate,(0,et.Lx)(...e)))}catch(t){throw ep(t,"endBefore()","Query.endBefore()")}}endAt(...e){try{return new ew(this.firestore,(0,et.IO)(this._delegate,(0,et.Wu)(...e)))}catch(t){throw ep(t,"endAt()","Query.endAt()")}}isEqual(e){return(0,et.iE)(this._delegate,e._delegate)}get(e){return((null==e?void 0:e.source)==="cache"?(0,et.UQ)(this._delegate):(null==e?void 0:e.source)==="server"?(0,et.zN)(this._delegate):(0,et.PL)(this._delegate)).then(e=>new eb(this.firestore,new et.W(this.firestore._delegate,this._userDataWriter,this._delegate,e._snapshot)))}onSnapshot(...e){let t=em(e),n=eg(e,e=>new eb(this.firestore,new et.W(this.firestore._delegate,this._userDataWriter,this._delegate,e._snapshot)));return(0,et.cf)(this._delegate,t,n)}withConverter(e){return new ew(this.firestore,e?this._delegate.withConverter(ed.getInstance(this.firestore,e)):this._delegate.withConverter(null))}}class e_{constructor(e,t){this._firestore=e,this._delegate=t}get type(){return this._delegate.type}get doc(){return new ev(this._firestore,this._delegate.doc)}get oldIndex(){return this._delegate.oldIndex}get newIndex(){return this._delegate.newIndex}}class eb{constructor(e,t){this._firestore=e,this._delegate=t}get query(){return new ew(this._firestore,this._delegate.query)}get metadata(){return this._delegate.metadata}get size(){return this._delegate.size}get empty(){return this._delegate.empty}get docs(){return this._delegate.docs.map(e=>new ev(this._firestore,e))}docChanges(e){return this._delegate.docChanges(e).map(e=>new e_(this._firestore,e))}forEach(e,t){this._delegate.forEach(n=>{e.call(t,new ev(this._firestore,n))})}isEqual(e){return(0,et.qK)(this._delegate,e._delegate)}}class eI extends ew{constructor(e,t){super(e,t),this.firestore=e,this._delegate=t}get id(){return this._delegate.id}get path(){return this._delegate.path}get parent(){let e=this._delegate.parent;return e?new ef(this.firestore,e):null}doc(e){try{if(void 0===e)return new ef(this.firestore,(0,et.JU)(this._delegate));return new ef(this.firestore,(0,et.JU)(this._delegate,e))}catch(t){throw ep(t,"doc()","CollectionReference.doc()")}}add(e){return(0,et.ET)(this._delegate,e).then(e=>new ef(this.firestore,e))}isEqual(e){return(0,et.Eo)(this._delegate,e._delegate)}withConverter(e){return new eI(this.firestore,e?this._delegate.withConverter(ed.getInstance(this.firestore,e)):this._delegate.withConverter(null))}}function eT(e){return(0,et.Cf)(e,et.my)}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class eE{constructor(...e){this._delegate=new et.Lz(...e)}static documentId(){return new eE(et.Xb.keyField().canonicalString())}isEqual(e){return(e=(0,u.m9)(e))instanceof et.Lz&&this._delegate._internalPath.isEqual(e._internalPath)}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class eS{constructor(e){this._delegate=e}static serverTimestamp(){let e=(0,et.Bt)();return e._methodName="FieldValue.serverTimestamp",new eS(e)}static delete(){let e=(0,et.AK)();return e._methodName="FieldValue.delete",new eS(e)}static arrayUnion(...e){let t=(0,et.vr)(...e);return t._methodName="FieldValue.arrayUnion",new eS(t)}static arrayRemove(...e){let t=(0,et.Ab)(...e);return t._methodName="FieldValue.arrayRemove",new eS(t)}static increment(e){let t=(0,et.nP)(e);return t._methodName="FieldValue.increment",new eS(t)}isEqual(e){return this._delegate.isEqual(e._delegate)}}/**
 * @license
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let ek={Firestore:el,GeoPoint:et.F8,Timestamp:et.EK,Blob:es,Transaction:ec,WriteBatch:eh,DocumentReference:ef,DocumentSnapshot:ey,Query:ew,QueryDocumentSnapshot:ev,QuerySnapshot:eb,CollectionReference:eI,FieldPath:eE,FieldValue:eS,setLogLevel:function(e){(0,et.Ub)(e)},CACHE_SIZE_UNLIMITED:et.IX};!function(e,t){e.INTERNAL.registerComponent(new c.wA("firestore-compat",e=>{let n=e.getProvider("app-compat").getImmediate(),r=e.getProvider("firestore").getImmediate();return t(n,r)},"PUBLIC").setServiceProps(Object.assign({},ek)))}(m,(e,t)=>new el(e,t,new eo)),m.registerVersion("@firebase/firestore-compat","0.3.0");/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let eA="firebasestorage.googleapis.com",eC="storageBucket";/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class ex extends u.ZR{constructor(e,t,n=0){super(eR(e),`Firebase Storage: ${t} (${eR(e)})`),this.status_=n,this.customData={serverResponse:null},this._baseMessage=this.message,Object.setPrototypeOf(this,ex.prototype)}get status(){return this.status_}set status(e){this.status_=e}_codeEquals(e){return eR(e)===this.code}get serverResponse(){return this.customData.serverResponse}set serverResponse(e){this.customData.serverResponse=e,this.customData.serverResponse?this.message=`${this._baseMessage}
${this.customData.serverResponse}`:this.message=this._baseMessage}}function eR(e){return"storage/"+e}function eD(){return new ex("unknown","An unknown error occurred, please check the error payload for server response.")}function eN(){return new ex("retry-limit-exceeded","Max retry time for operation exceeded, please try again.")}function eO(){return new ex("canceled","User canceled the upload/download.")}function eP(){return new ex("cannot-slice-blob","Cannot slice blob for upload. Please retry the upload.")}function eL(e){return new ex("invalid-argument",e)}function eM(){return new ex("app-deleted","The Firebase app was deleted.")}function eF(e){return new ex("invalid-root-operation","The operation '"+e+"' cannot be performed on a root reference, create a non-root reference using child, such as .child('file.png').")}function eU(e,t){return new ex("invalid-format","String does not match format '"+e+"': "+t)}function eV(e){throw new ex("internal-error","Internal error: "+e)}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class eq{constructor(e,t){this.bucket=e,this.path_=t}get path(){return this.path_}get isRoot(){return 0===this.path.length}fullServerUrl(){let e=encodeURIComponent;return"/b/"+e(this.bucket)+"/o/"+e(this.path)}bucketOnlyServerUrl(){let e=encodeURIComponent;return"/b/"+e(this.bucket)+"/o"}static makeFromBucketSpec(e,t){let n;try{n=eq.makeFromUrl(e,t)}catch(r){return new eq(e,"")}if(""===n.path)return n;throw new ex("invalid-default-bucket","Invalid default bucket '"+e+"'.")}static makeFromUrl(e,t){let n=null,r="([A-Za-z0-9.\\-_]+)",i=RegExp("^gs://"+r+"(/(.*))?$","i");function s(e){e.path_=decodeURIComponent(e.path)}let a=t.replace(/[.]/g,"\\."),o=RegExp(`^https?://${a}/v[A-Za-z0-9_]+/b/${r}/o(/([^?#]*).*)?$`,"i"),l=RegExp(`^https?://${t===eA?"(?:storage.googleapis.com|storage.cloud.google.com)":t}/${r}/([^?#]*)`,"i"),u=[{regex:i,indices:{bucket:1,path:3},postModify:function(e){"/"===e.path.charAt(e.path.length-1)&&(e.path_=e.path_.slice(0,-1))}},{regex:o,indices:{bucket:1,path:3},postModify:s},{regex:l,indices:{bucket:1,path:2},postModify:s}];for(let c=0;c<u.length;c++){let h=u[c],d=h.regex.exec(e);if(d){let f=d[h.indices.bucket],p=d[h.indices.path];p||(p=""),n=new eq(f,p),h.postModify(n);break}}if(null==n)throw new ex("invalid-url","Invalid URL '"+e+"'.");return n}}class eB{constructor(e){this.promise_=Promise.reject(e)}getPromise(){return this.promise_}cancel(e=!1){}}function ej(e){return"string"==typeof e||e instanceof String}function e$(e){return ez()&&e instanceof Blob}function ez(){return"undefined"!=typeof Blob&&!(0,u.UG)()}function eG(e,t,n,r){if(r<t)throw eL(`Invalid value for '${e}'. Expected ${t} or greater.`);if(r>n)throw eL(`Invalid value for '${e}'. Expected ${n} or less.`)}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function eK(e,t,n){let r=t;return null==n&&(r=`https://${t}`),`${n}://${r}/v0${e}`}function eH(e){let t=encodeURIComponent,n="?";for(let r in e)if(e.hasOwnProperty(r)){let i=t(r)+"="+t(e[r]);n=n+i+"&"}return n.slice(0,-1)}/**
 * @license
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function eW(e,t){let n=-1!==[408,429].indexOf(e),r=-1!==t.indexOf(e);return e>=500&&e<600||n||r}(o=l||(l={}))[o.NO_ERROR=0]="NO_ERROR",o[o.NETWORK_ERROR=1]="NETWORK_ERROR",o[o.ABORT=2]="ABORT";/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class eQ{constructor(e,t,n,r,i,s,a,o,l,u,c,h=!0){this.url_=e,this.method_=t,this.headers_=n,this.body_=r,this.successCodes_=i,this.additionalRetryCodes_=s,this.callback_=a,this.errorCallback_=o,this.timeout_=l,this.progressCallback_=u,this.connectionFactory_=c,this.retry=h,this.pendingConnection_=null,this.backoffId_=null,this.canceled_=!1,this.appDelete_=!1,this.promise_=new Promise((e,t)=>{this.resolve_=e,this.reject_=t,this.start_()})}start_(){let e=(e,t)=>{if(t){e(!1,new eY(!1,null,!0));return}let n=this.connectionFactory_();this.pendingConnection_=n;let r=e=>{let t=e.loaded,n=e.lengthComputable?e.total:-1;null!==this.progressCallback_&&this.progressCallback_(t,n)};null!==this.progressCallback_&&n.addUploadProgressListener(r),n.send(this.url_,this.method_,this.body_,this.headers_).then(()=>{null!==this.progressCallback_&&n.removeUploadProgressListener(r),this.pendingConnection_=null;let t=n.getErrorCode()===l.NO_ERROR,i=n.getStatus();if((!t||eW(i,this.additionalRetryCodes_))&&this.retry){let s=n.getErrorCode()===l.ABORT;e(!1,new eY(!1,null,s));return}let a=-1!==this.successCodes_.indexOf(i);e(!0,new eY(a,n))})},t=(e,t)=>{let n=this.resolve_,r=this.reject_,i=t.connection;if(t.wasSuccessCode)try{let s=this.callback_(i,i.getResponse());void 0!==s?n(s):n()}catch(a){r(a)}else if(null!==i){let o=eD();o.serverResponse=i.getErrorText(),r(this.errorCallback_?this.errorCallback_(i,o):o)}else if(t.canceled){let l=this.appDelete_?eM():eO();r(l)}else{let u=eN();r(u)}};this.canceled_?t(!1,new eY(!1,null,!0)):this.backoffId_=/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function(e,t,n){let r=1,i=null,s=null,a=!1,o=0,l=!1;function u(...e){l||(l=!0,t.apply(null,e))}function c(t){i=setTimeout(()=>{i=null,e(d,2===o)},t)}function h(){s&&clearTimeout(s)}function d(e,...t){let n;if(l){h();return}if(e){h(),u.call(null,e,...t);return}let i=2===o||a;if(i){h(),u.call(null,e,...t);return}r<64&&(r*=2),1===o?(o=2,n=0):n=(r+Math.random())*1e3,c(n)}let f=!1;function p(e){!f&&(f=!0,h(),!l&&(null!==i?(e||(o=2),clearTimeout(i),c(0)):e||(o=1)))}return c(0),s=setTimeout(()=>{a=!0,p(!0)},n),p}(e,t,this.timeout_)}getPromise(){return this.promise_}cancel(e){this.canceled_=!0,this.appDelete_=e||!1,null!==this.backoffId_&&(0,this.backoffId_)(!1),null!==this.pendingConnection_&&this.pendingConnection_.abort()}}class eY{constructor(e,t,n){this.wasSuccessCode=e,this.connection=t,this.canceled=!!n}}function eX(...e){let t="undefined"!=typeof BlobBuilder?BlobBuilder:"undefined"!=typeof WebKitBlobBuilder?WebKitBlobBuilder:void 0;if(void 0!==t){let n=new t;for(let r=0;r<e.length;r++)n.append(e[r]);return n.getBlob()}if(ez())return new Blob(e);throw new ex("unsupported-environment","This browser doesn't seem to support creating Blobs")}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let eJ={RAW:"raw",BASE64:"base64",BASE64URL:"base64url",DATA_URL:"data_url"};class eZ{constructor(e,t){this.data=e,this.contentType=t||null}}function e0(e,t){switch(e){case eJ.RAW:return new eZ(e1(t));case eJ.BASE64:case eJ.BASE64URL:return new eZ(e2(e,t));case eJ.DATA_URL:return new eZ(function(e){let t=new e4(e);return t.base64?e2(eJ.BASE64,t.rest):function(e){let t;try{t=decodeURIComponent(e)}catch(n){throw eU(eJ.DATA_URL,"Malformed data URL.")}return e1(t)}(t.rest)}(t),function(e){let t=new e4(e);return t.contentType}(t))}throw eD()}function e1(e){let t=[];for(let n=0;n<e.length;n++){let r=e.charCodeAt(n);if(r<=127)t.push(r);else if(r<=2047)t.push(192|r>>6,128|63&r);else if((64512&r)==55296){let i=n<e.length-1&&(64512&e.charCodeAt(n+1))==56320;if(i){let s=r,a=e.charCodeAt(++n);r=65536|(1023&s)<<10|1023&a,t.push(240|r>>18,128|r>>12&63,128|r>>6&63,128|63&r)}else t.push(239,191,189)}else(64512&r)==56320?t.push(239,191,189):t.push(224|r>>12,128|r>>6&63,128|63&r)}return new Uint8Array(t)}function e2(e,t){let n;switch(e){case eJ.BASE64:{let r=-1!==t.indexOf("-"),i=-1!==t.indexOf("_");if(r||i)throw eU(e,"Invalid character '"+(r?"-":"_")+"' found: is it base64url encoded?");break}case eJ.BASE64URL:{let s=-1!==t.indexOf("+"),a=-1!==t.indexOf("/");if(s||a)throw eU(e,"Invalid character '"+(s?"+":"/")+"' found: is it base64 encoded?");t=t.replace(/-/g,"+").replace(/_/g,"/")}}try{n=/**
 * @license
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function(e){if("undefined"==typeof atob)throw new ex("unsupported-environment","base-64 is missing. Make sure to install the required polyfills. See https://firebase.google.com/docs/web/environments-js-sdk#polyfills for more information.");return atob(e)}(t)}catch(o){if(o.message.includes("polyfill"))throw o;throw eU(e,"Invalid character found")}let l=new Uint8Array(n.length);for(let u=0;u<n.length;u++)l[u]=n.charCodeAt(u);return l}class e4{constructor(e){this.base64=!1,this.contentType=null;let t=e.match(/^data:([^,]+)?,/);if(null===t)throw eU(eJ.DATA_URL,"Must be formatted 'data:[<mediatype>][;base64],<data>");let n=t[1]||null;null!=n&&(this.base64=function(e,t){let n=e.length>=t.length;return!!n&&e.substring(e.length-t.length)===t}(n,";base64"),this.contentType=this.base64?n.substring(0,n.length-7):n),this.rest=e.substring(e.indexOf(",")+1)}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class e3{constructor(e,t){let n=0,r="";e$(e)?(this.data_=e,n=e.size,r=e.type):e instanceof ArrayBuffer?(t?this.data_=new Uint8Array(e):(this.data_=new Uint8Array(e.byteLength),this.data_.set(new Uint8Array(e))),n=this.data_.length):e instanceof Uint8Array&&(t?this.data_=e:(this.data_=new Uint8Array(e.length),this.data_.set(e)),n=e.length),this.size_=n,this.type_=r}size(){return this.size_}type(){return this.type_}slice(e,t){if(e$(this.data_)){let n=this.data_,r=n.webkitSlice?n.webkitSlice(e,t):n.mozSlice?n.mozSlice(e,t):n.slice?n.slice(e,t):null;return null===r?null:new e3(r)}{let i=new Uint8Array(this.data_.buffer,e,t-e);return new e3(i,!0)}}static getBlob(...e){if(ez()){let t=e.map(e=>e instanceof e3?e.data_:e);return new e3(eX.apply(null,t))}{let n=e.map(e=>ej(e)?e0(eJ.RAW,e).data:e.data_),r=0;n.forEach(e=>{r+=e.byteLength});let i=new Uint8Array(r),s=0;return n.forEach(e=>{for(let t=0;t<e.length;t++)i[s++]=e[t]}),new e3(i,!0)}}uploadData(){return this.data_}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function e6(e){var t;let n;try{n=JSON.parse(e)}catch(r){return null}return"object"!=typeof(t=n)||Array.isArray(t)?null:n}function e5(e){let t=e.lastIndexOf("/",e.length-2);return -1===t?e:e.slice(t+1)}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function e9(e,t){return t}class e8{constructor(e,t,n,r){this.server=e,this.local=t||e,this.writable=!!n,this.xform=r||e9}}let e7=null;function te(){if(e7)return e7;let e=[];e.push(new e8("bucket")),e.push(new e8("generation")),e.push(new e8("metageneration")),e.push(new e8("name","fullPath",!0));let t=new e8("name");t.xform=function(e,t){return!ej(t)||t.length<2?t:e5(t)},e.push(t);let n=new e8("size");return n.xform=function(e,t){return void 0!==t?Number(t):t},e.push(n),e.push(new e8("timeCreated")),e.push(new e8("updated")),e.push(new e8("md5Hash",null,!0)),e.push(new e8("cacheControl",null,!0)),e.push(new e8("contentDisposition",null,!0)),e.push(new e8("contentEncoding",null,!0)),e.push(new e8("contentLanguage",null,!0)),e.push(new e8("contentType",null,!0)),e.push(new e8("metadata","customMetadata",!0)),e7=e}function tt(e,t,n){let r=e6(t);return null===r?null:function(e,t,n){let r={};r.type="file";let i=n.length;for(let s=0;s<i;s++){let a=n[s];r[a.local]=a.xform(r,t[a.server])}return Object.defineProperty(r,"ref",{get:function(){let t=r.bucket,n=r.fullPath,i=new eq(t,n);return e._makeStorageReference(i)}}),r}(e,r,n)}function tn(e,t){let n={},r=t.length;for(let i=0;i<r;i++){let s=t[i];s.writable&&(n[s.server]=e[s.local])}return JSON.stringify(n)}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let tr="prefixes",ti="items";class ts{constructor(e,t,n,r){this.url=e,this.method=t,this.handler=n,this.timeout=r,this.urlParams={},this.headers={},this.body=null,this.errorHandler=null,this.progressCallback=null,this.successCodes=[200],this.additionalRetryCodes=[]}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function ta(e){if(!e)throw eD()}function to(e,t){return function(n,r){let i=tt(e,r,t);return ta(null!==i),i}}function tl(e){return function(t,n){var r,i;let s;return 401===t.getStatus()?s=t.getErrorText().includes("Firebase App Check token is invalid")?new ex("unauthorized-app","This app does not have permission to access Firebase Storage on this project."):new ex("unauthenticated","User is not authenticated, please authenticate using Firebase Authentication and try again."):402===t.getStatus()?(r=e.bucket,s=new ex("quota-exceeded","Quota for bucket '"+r+"' exceeded, please view quota on https://firebase.google.com/pricing/.")):403===t.getStatus()?(i=e.path,s=new ex("unauthorized","User does not have permission to access '"+i+"'.")):s=n,s.status=t.getStatus(),s.serverResponse=n.serverResponse,s}}function tu(e){let t=tl(e);return function(n,r){let i=t(n,r);if(404===n.getStatus()){var s;s=e.path,i=new ex("object-not-found","Object '"+s+"' does not exist.")}return i.serverResponse=r.serverResponse,i}}function tc(e,t,n){let r=t.fullServerUrl(),i=eK(r,e.host,e._protocol),s=e.maxOperationRetryTime,a=new ts(i,"GET",to(e,n),s);return a.errorHandler=tu(t),a}function th(e,t,n){let r=Object.assign({},n);return r.fullPath=e.path,r.size=t.size(),!r.contentType&&(r.contentType=t&&t.type()||"application/octet-stream"),r}class td{constructor(e,t,n,r){this.current=e,this.total=t,this.finalized=!!n,this.metadata=r||null}}function tf(e,t){let n=null;try{n=e.getResponseHeader("X-Goog-Upload-Status")}catch(r){ta(!1)}return ta(!!n&&-1!==(t||["active"]).indexOf(n)),n}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let tp={RUNNING:"running",PAUSED:"paused",SUCCESS:"success",CANCELED:"canceled",ERROR:"error"};function tm(e){switch(e){case"running":case"pausing":case"canceling":return tp.RUNNING;case"paused":return tp.PAUSED;case"success":return tp.SUCCESS;case"canceled":return tp.CANCELED;default:return tp.ERROR}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class tg{constructor(e,t,n){"function"==typeof e||null!=t||null!=n?(this.next=e,this.error=null!=t?t:void 0,this.complete=null!=n?n:void 0):(this.next=e.next,this.error=e.error,this.complete=e.complete)}}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function ty(e){return(...t)=>{Promise.resolve().then(()=>e(...t))}}class tv{constructor(){this.sent_=!1,this.xhr_=new XMLHttpRequest,this.initXhr(),this.errorCode_=l.NO_ERROR,this.sendPromise_=new Promise(e=>{this.xhr_.addEventListener("abort",()=>{this.errorCode_=l.ABORT,e()}),this.xhr_.addEventListener("error",()=>{this.errorCode_=l.NETWORK_ERROR,e()}),this.xhr_.addEventListener("load",()=>{e()})})}send(e,t,n,r){if(this.sent_)throw eV("cannot .send() more than once");if(this.sent_=!0,this.xhr_.open(t,e,!0),void 0!==r)for(let i in r)r.hasOwnProperty(i)&&this.xhr_.setRequestHeader(i,r[i].toString());return void 0!==n?this.xhr_.send(n):this.xhr_.send(),this.sendPromise_}getErrorCode(){if(!this.sent_)throw eV("cannot .getErrorCode() before sending");return this.errorCode_}getStatus(){if(!this.sent_)throw eV("cannot .getStatus() before sending");try{return this.xhr_.status}catch(e){return -1}}getResponse(){if(!this.sent_)throw eV("cannot .getResponse() before sending");return this.xhr_.response}getErrorText(){if(!this.sent_)throw eV("cannot .getErrorText() before sending");return this.xhr_.statusText}abort(){this.xhr_.abort()}getResponseHeader(e){return this.xhr_.getResponseHeader(e)}addUploadProgressListener(e){null!=this.xhr_.upload&&this.xhr_.upload.addEventListener("progress",e)}removeUploadProgressListener(e){null!=this.xhr_.upload&&this.xhr_.upload.removeEventListener("progress",e)}}class tw extends tv{initXhr(){this.xhr_.responseType="text"}}function t_(){return new tw}/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class tb{constructor(e,t,n=null){this._transferred=0,this._needToFetchStatus=!1,this._needToFetchMetadata=!1,this._observers=[],this._error=void 0,this._uploadUrl=void 0,this._request=void 0,this._chunkMultiplier=1,this._resolve=void 0,this._reject=void 0,this._ref=e,this._blob=t,this._metadata=n,this._mappings=te(),this._resumable=this._shouldDoResumable(this._blob),this._state="running",this._errorHandler=e=>{if(this._request=void 0,this._chunkMultiplier=1,e._codeEquals("canceled"))this._needToFetchStatus=!0,this.completeTransitions_();else{let t=this.isExponentialBackoffExpired();if(eW(e.status,[])){if(t)e=eN();else{this.sleepTime=Math.max(2*this.sleepTime,1e3),this._needToFetchStatus=!0,this.completeTransitions_();return}}this._error=e,this._transition("error")}},this._metadataErrorHandler=e=>{this._request=void 0,e._codeEquals("canceled")?this.completeTransitions_():(this._error=e,this._transition("error"))},this.sleepTime=0,this.maxSleepTime=this._ref.storage.maxUploadRetryTime,this._promise=new Promise((e,t)=>{this._resolve=e,this._reject=t,this._start()}),this._promise.then(null,()=>{})}isExponentialBackoffExpired(){return this.sleepTime>this.maxSleepTime}_makeProgressCallback(){let e=this._transferred;return t=>this._updateProgress(e+t)}_shouldDoResumable(e){return e.size()>262144}_start(){"running"===this._state&&void 0===this._request&&(this._resumable?void 0===this._uploadUrl?this._createResumable():this._needToFetchStatus?this._fetchStatus():this._needToFetchMetadata?this._fetchMetadata():this.pendingTimeout=setTimeout(()=>{this.pendingTimeout=void 0,this._continueUpload()},this.sleepTime):this._oneShotUpload())}_resolveToken(e){Promise.all([this._ref.storage._getAuthToken(),this._ref.storage._getAppCheckToken()]).then(([t,n])=>{switch(this._state){case"running":e(t,n);break;case"canceling":this._transition("canceled");break;case"pausing":this._transition("paused")}})}_createResumable(){this._resolveToken((e,t)=>{let n=function(e,t,n,r,i){let s=t.bucketOnlyServerUrl(),a=th(t,r,i),o={name:a.fullPath},l=eK(s,e.host,e._protocol),u={"X-Goog-Upload-Protocol":"resumable","X-Goog-Upload-Command":"start","X-Goog-Upload-Header-Content-Length":`${r.size()}`,"X-Goog-Upload-Header-Content-Type":a.contentType,"Content-Type":"application/json; charset=utf-8"},c=tn(a,n),h=e.maxUploadRetryTime,d=new ts(l,"POST",function(e){let t;tf(e);try{t=e.getResponseHeader("X-Goog-Upload-URL")}catch(n){ta(!1)}return ta(ej(t)),t},h);return d.urlParams=o,d.headers=u,d.body=c,d.errorHandler=tl(t),d}(this._ref.storage,this._ref._location,this._mappings,this._blob,this._metadata),r=this._ref.storage._makeRequest(n,t_,e,t);this._request=r,r.getPromise().then(e=>{this._request=void 0,this._uploadUrl=e,this._needToFetchStatus=!1,this.completeTransitions_()},this._errorHandler)})}_fetchStatus(){let e=this._uploadUrl;this._resolveToken((t,n)=>{let r=function(e,t,n,r){let i=e.maxUploadRetryTime,s=new ts(n,"POST",function(e){let t=tf(e,["active","final"]),n=null;try{n=e.getResponseHeader("X-Goog-Upload-Size-Received")}catch(i){ta(!1)}n||ta(!1);let s=Number(n);return ta(!isNaN(s)),new td(s,r.size(),"final"===t)},i);return s.headers={"X-Goog-Upload-Command":"query"},s.errorHandler=tl(t),s}(this._ref.storage,this._ref._location,e,this._blob),i=this._ref.storage._makeRequest(r,t_,t,n);this._request=i,i.getPromise().then(e=>{this._request=void 0,this._updateProgress(e.current),this._needToFetchStatus=!1,e.finalized&&(this._needToFetchMetadata=!0),this.completeTransitions_()},this._errorHandler)})}_continueUpload(){let e=262144*this._chunkMultiplier,t=new td(this._transferred,this._blob.size()),n=this._uploadUrl;this._resolveToken((r,i)=>{let s;try{s=function(e,t,n,r,i,s,a,o){let l=new td(0,0);if(a?(l.current=a.current,l.total=a.total):(l.current=0,l.total=r.size()),r.size()!==l.total)throw new ex("server-file-wrong-size","Server recorded incorrect upload file size, please retry the upload.");let u=l.total-l.current,c=u;i>0&&(c=Math.min(c,i));let h=l.current,d=h+c,f="";f=0===c?"finalize":u===c?"upload, finalize":"upload";let p={"X-Goog-Upload-Command":f,"X-Goog-Upload-Offset":`${l.current}`},m=r.slice(h,d);if(null===m)throw eP();let g=t.maxUploadRetryTime,y=new ts(n,"POST",function(e,n){let i;let a=tf(e,["active","final"]),o=l.current+c,u=r.size();return i="final"===a?to(t,s)(e,n):null,new td(o,u,"final"===a,i)},g);return y.headers=p,y.body=m.uploadData(),y.progressCallback=o||null,y.errorHandler=tl(e),y}(this._ref._location,this._ref.storage,n,this._blob,e,this._mappings,t,this._makeProgressCallback())}catch(a){this._error=a,this._transition("error");return}let o=this._ref.storage._makeRequest(s,t_,r,i,!1);this._request=o,o.getPromise().then(e=>{this._increaseMultiplier(),this._request=void 0,this._updateProgress(e.current),e.finalized?(this._metadata=e.metadata,this._transition("success")):this.completeTransitions_()},this._errorHandler)})}_increaseMultiplier(){let e=262144*this._chunkMultiplier;2*e<33554432&&(this._chunkMultiplier*=2)}_fetchMetadata(){this._resolveToken((e,t)=>{let n=tc(this._ref.storage,this._ref._location,this._mappings),r=this._ref.storage._makeRequest(n,t_,e,t);this._request=r,r.getPromise().then(e=>{this._request=void 0,this._metadata=e,this._transition("success")},this._metadataErrorHandler)})}_oneShotUpload(){this._resolveToken((e,t)=>{let n=function(e,t,n,r,i){let s=t.bucketOnlyServerUrl(),a={"X-Goog-Upload-Protocol":"multipart"},o=function(){let e="";for(let t=0;t<2;t++)e+=Math.random().toString().slice(2);return e}();a["Content-Type"]="multipart/related; boundary="+o;let l=th(t,r,i),u=tn(l,n),c="--"+o+"\r\nContent-Type: application/json; charset=utf-8\r\n\r\n"+u+"\r\n--"+o+"\r\nContent-Type: "+l.contentType+"\r\n\r\n",h=e3.getBlob(c,r,"\r\n--"+o+"--");if(null===h)throw eP();let d={name:l.fullPath},f=eK(s,e.host,e._protocol),p=e.maxUploadRetryTime,m=new ts(f,"POST",to(e,n),p);return m.urlParams=d,m.headers=a,m.body=h.uploadData(),m.errorHandler=tl(t),m}(this._ref.storage,this._ref._location,this._mappings,this._blob,this._metadata),r=this._ref.storage._makeRequest(n,t_,e,t);this._request=r,r.getPromise().then(e=>{this._request=void 0,this._metadata=e,this._updateProgress(this._blob.size()),this._transition("success")},this._errorHandler)})}_updateProgress(e){let t=this._transferred;this._transferred=e,this._transferred!==t&&this._notifyObservers()}_transition(e){if(this._state!==e)switch(e){case"canceling":case"pausing":this._state=e,void 0!==this._request?this._request.cancel():this.pendingTimeout&&(clearTimeout(this.pendingTimeout),this.pendingTimeout=void 0,this.completeTransitions_());break;case"running":let t="paused"===this._state;this._state=e,t&&(this._notifyObservers(),this._start());break;case"paused":case"error":case"success":this._state=e,this._notifyObservers();break;case"canceled":this._error=eO(),this._state=e,this._notifyObservers()}}completeTransitions_(){switch(this._state){case"pausing":this._transition("paused");break;case"canceling":this._transition("canceled");break;case"running":this._start()}}get snapshot(){let e=tm(this._state);return{bytesTransferred:this._transferred,totalBytes:this._blob.size(),state:e,metadata:this._metadata,task:this,ref:this._ref}}on(e,t,n,r){let i=new tg(t||void 0,n||void 0,r||void 0);return this._addObserver(i),()=>{this._removeObserver(i)}}then(e,t){return this._promise.then(e,t)}catch(e){return this.then(null,e)}_addObserver(e){this._observers.push(e),this._notifyObserver(e)}_removeObserver(e){let t=this._observers.indexOf(e);-1!==t&&this._observers.splice(t,1)}_notifyObservers(){this._finishPromise();let e=this._observers.slice();e.forEach(e=>{this._notifyObserver(e)})}_finishPromise(){if(void 0!==this._resolve){let e=!0;switch(tm(this._state)){case tp.SUCCESS:ty(this._resolve.bind(null,this.snapshot))();break;case tp.CANCELED:case tp.ERROR:let t=this._reject;ty(t.bind(null,this._error))();break;default:e=!1}e&&(this._resolve=void 0,this._reject=void 0)}}_notifyObserver(e){let t=tm(this._state);switch(t){case tp.RUNNING:case tp.PAUSED:e.next&&ty(e.next.bind(e,this.snapshot))();break;case tp.SUCCESS:e.complete&&ty(e.complete.bind(e))();break;case tp.CANCELED:case tp.ERROR:default:e.error&&ty(e.error.bind(e,this._error))()}}resume(){let e="paused"===this._state||"pausing"===this._state;return e&&this._transition("running"),e}pause(){let e="running"===this._state;return e&&this._transition("pausing"),e}cancel(){let e="running"===this._state||"pausing"===this._state;return e&&this._transition("canceling"),e}}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class tI{constructor(e,t){this._service=e,t instanceof eq?this._location=t:this._location=eq.makeFromUrl(t,e.host)}toString(){return"gs://"+this._location.bucket+"/"+this._location.path}_newRef(e,t){return new tI(e,t)}get root(){let e=new eq(this._location.bucket,"");return this._newRef(this._service,e)}get bucket(){return this._location.bucket}get fullPath(){return this._location.path}get name(){return e5(this._location.path)}get storage(){return this._service}get parent(){let e=/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function(e){if(0===e.length)return null;let t=e.lastIndexOf("/");if(-1===t)return"";let n=e.slice(0,t);return n}(this._location.path);if(null===e)return null;let t=new eq(this._location.bucket,e);return new tI(this._service,t)}_throwIfRoot(e){if(""===this._location.path)throw eF(e)}}async function tT(e,t,n){let r=await tE(e,{pageToken:n});t.prefixes.push(...r.prefixes),t.items.push(...r.items),null!=r.nextPageToken&&await tT(e,t,r.nextPageToken)}function tE(e,t){null!=t&&"number"==typeof t.maxResults&&eG("options.maxResults",1,1e3,t.maxResults);let n=t||{},r=function(e,t,n,r,i){var s;let a={};t.isRoot?a.prefix="":a.prefix=t.path+"/",n&&n.length>0&&(a.delimiter=n),r&&(a.pageToken=r),i&&(a.maxResults=i);let o=t.bucketOnlyServerUrl(),l=eK(o,e.host,e._protocol),u=e.maxOperationRetryTime,c=new ts(l,"GET",(s=t.bucket,function(t,n){let r=function(e,t,n){let r=e6(n);return null===r?null:function(e,t,n){let r={prefixes:[],items:[],nextPageToken:n.nextPageToken};if(n[tr])for(let i of n[tr]){let s=i.replace(/\/$/,""),a=e._makeStorageReference(new eq(t,s));r.prefixes.push(a)}if(n[ti])for(let o of n[ti]){let l=e._makeStorageReference(new eq(t,o.name));r.items.push(l)}return r}(e,t,r)}(e,s,n);return ta(null!==r),r}),u);return c.urlParams=a,c.errorHandler=tl(t),c}(e.storage,e._location,"/",n.pageToken,n.maxResults);return e.storage.makeRequestWithTokens(r,t_)}function tS(e,t){let n=function(e,t){let n=t.split("/").filter(e=>e.length>0).join("/");return 0===e.length?n:e+"/"+n}(e._location.path,t),r=new eq(e._location.bucket,n);return new tI(e.storage,r)}function tk(e,t){let n=null==t?void 0:t[eC];return null==n?null:eq.makeFromBucketSpec(n,e)}class tA{constructor(e,t,n,r,i){this.app=e,this._authProvider=t,this._appCheckProvider=n,this._url=r,this._firebaseVersion=i,this._bucket=null,this._host=eA,this._protocol="https",this._appId=null,this._deleted=!1,this._maxOperationRetryTime=12e4,this._maxUploadRetryTime=6e5,this._requests=new Set,null!=r?this._bucket=eq.makeFromBucketSpec(r,this._host):this._bucket=tk(this._host,this.app.options)}get host(){return this._host}set host(e){this._host=e,null!=this._url?this._bucket=eq.makeFromBucketSpec(this._url,e):this._bucket=tk(e,this.app.options)}get maxUploadRetryTime(){return this._maxUploadRetryTime}set maxUploadRetryTime(e){eG("time",0,Number.POSITIVE_INFINITY,e),this._maxUploadRetryTime=e}get maxOperationRetryTime(){return this._maxOperationRetryTime}set maxOperationRetryTime(e){eG("time",0,Number.POSITIVE_INFINITY,e),this._maxOperationRetryTime=e}async _getAuthToken(){if(this._overrideAuthToken)return this._overrideAuthToken;let e=this._authProvider.getImmediate({optional:!0});if(e){let t=await e.getToken();if(null!==t)return t.accessToken}return null}async _getAppCheckToken(){let e=this._appCheckProvider.getImmediate({optional:!0});if(e){let t=await e.getToken();return t.token}return null}_delete(){return this._deleted||(this._deleted=!0,this._requests.forEach(e=>e.cancel()),this._requests.clear()),Promise.resolve()}_makeStorageReference(e){return new tI(this,e)}_makeRequest(e,t,n,r,i=!0){if(this._deleted)return new eB(eM());{let s=function(e,t,n,r,i,s,a=!0){var o,l,u;let c=eH(e.urlParams),h=e.url+c,d=Object.assign({},e.headers);return o=d,t&&(o["X-Firebase-GMPID"]=t),l=d,null!==n&&n.length>0&&(l.Authorization="Firebase "+n),d["X-Firebase-Storage-Version"]="webjs/"+(null!=s?s:"AppManager"),u=d,null!==r&&(u["X-Firebase-AppCheck"]=r),new eQ(h,e.method,d,e.body,e.successCodes,e.additionalRetryCodes,e.handler,e.errorHandler,e.timeout,e.progressCallback,i,a)}(e,this._appId,n,r,t,this._firebaseVersion,i);return this._requests.add(s),s.getPromise().then(()=>this._requests.delete(s),()=>this._requests.delete(s)),s}}async makeRequestWithTokens(e,t){let[n,r]=await Promise.all([this._getAuthToken(),this._getAppCheckToken()]);return this._makeRequest(e,t,n,r).getPromise()}}let tC="@firebase/storage",tx="0.10.0";function tR(e,t){return function(e,t){if(!(t&&/^[A-Za-z]+:\/\//.test(t)))return function e(t,n){if(t instanceof tA){if(null==t._bucket)throw new ex("no-default-bucket","No default bucket found. Did you set the '"+eC+"' property when initializing the app?");let r=new tI(t,t._bucket);return null!=n?e(r,n):r}return void 0!==n?tS(t,n):t}(e,t);if(e instanceof tA)return new tI(e,t);throw eL("To use ref(service, url), the first argument must be a Storage instance.")}(e=(0,u.m9)(e),t)}(0,h._registerComponent)(new c.wA("storage",function(e,{instanceIdentifier:t}){let n=e.getProvider("app").getImmediate(),r=e.getProvider("auth-internal"),i=e.getProvider("app-check-internal");return new tA(n,r,i,t,h.SDK_VERSION)},"PUBLIC").setMultipleInstances(!0)),(0,h.registerVersion)(tC,tx,""),(0,h.registerVersion)(tC,tx,"esm2017");/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class tD{constructor(e,t,n){this._delegate=e,this.task=t,this.ref=n}get bytesTransferred(){return this._delegate.bytesTransferred}get metadata(){return this._delegate.metadata}get state(){return this._delegate.state}get totalBytes(){return this._delegate.totalBytes}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class tN{constructor(e,t){this._delegate=e,this._ref=t,this.cancel=this._delegate.cancel.bind(this._delegate),this.catch=this._delegate.catch.bind(this._delegate),this.pause=this._delegate.pause.bind(this._delegate),this.resume=this._delegate.resume.bind(this._delegate)}get snapshot(){return new tD(this._delegate.snapshot,this,this._ref)}then(e,t){return this._delegate.then(t=>{if(e)return e(new tD(t,this,this._ref))},t)}on(e,t,n,r){let i;return t&&(i="function"==typeof t?e=>t(new tD(e,this,this._ref)):{next:t.next?e=>t.next(new tD(e,this,this._ref)):void 0,complete:t.complete||void 0,error:t.error||void 0}),this._delegate.on(e,i,n||void 0,r||void 0)}}class tO{constructor(e,t){this._delegate=e,this._service=t}get prefixes(){return this._delegate.prefixes.map(e=>new tP(e,this._service))}get items(){return this._delegate.items.map(e=>new tP(e,this._service))}get nextPageToken(){return this._delegate.nextPageToken||null}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class tP{constructor(e,t){this._delegate=e,this.storage=t}get name(){return this._delegate.name}get bucket(){return this._delegate.bucket}get fullPath(){return this._delegate.fullPath}toString(){return this._delegate.toString()}child(e){let t=tS(this._delegate,e);return new tP(t,this.storage)}get root(){return new tP(this._delegate.root,this.storage)}get parent(){let e=this._delegate.parent;return null==e?null:new tP(e,this.storage)}put(e,t){var n,r;return this._throwIfRoot("put"),new tN((n=this._delegate,(r=n=(0,u.m9)(n))._throwIfRoot("uploadBytesResumable"),new tb(r,new e3(e),t)),this)}putString(e,t=eJ.RAW,n){this._throwIfRoot("putString");let r=e0(t,e),i=Object.assign({},n);return null==i.contentType&&null!=r.contentType&&(i.contentType=r.contentType),new tN(new tb(this._delegate,new e3(r.data,!0),i),this)}listAll(){var e;return(e=this._delegate,function(e){let t={prefixes:[],items:[]};return tT(e,t).then(()=>t)}(e=(0,u.m9)(e))).then(e=>new tO(e,this.storage))}list(e){var t;return(t=this._delegate,tE(t=(0,u.m9)(t),e||void 0)).then(e=>new tO(e,this.storage))}getMetadata(){var e;return e=this._delegate,function(e){e._throwIfRoot("getMetadata");let t=tc(e.storage,e._location,te());return e.storage.makeRequestWithTokens(t,t_)}(e=(0,u.m9)(e))}updateMetadata(e){var t;return t=this._delegate,function(e,t){e._throwIfRoot("updateMetadata");let n=function(e,t,n,r){let i=t.fullServerUrl(),s=eK(i,e.host,e._protocol),a=tn(n,r),o=e.maxOperationRetryTime,l=new ts(s,"PATCH",to(e,r),o);return l.headers={"Content-Type":"application/json; charset=utf-8"},l.body=a,l.errorHandler=tu(t),l}(e.storage,e._location,t,te());return e.storage.makeRequestWithTokens(n,t_)}(t=(0,u.m9)(t),e)}getDownloadURL(){var e;return e=this._delegate,function(e){e._throwIfRoot("getDownloadURL");let t=function(e,t,n){let r=t.fullServerUrl(),i=eK(r,e.host,e._protocol),s=e.maxOperationRetryTime,a=new ts(i,"GET",function(t,r){let i=tt(e,r,n);return ta(null!==i),function(e,t,n,r){let i=e6(t);if(null===i||!ej(i.downloadTokens))return null;let s=i.downloadTokens;if(0===s.length)return null;let a=encodeURIComponent,o=s.split(","),l=o.map(t=>{let i=e.bucket,s=e.fullPath,o="/b/"+a(i)+"/o/"+a(s),l=eK(o,n,r),u=eH({alt:"media",token:t});return l+u});return l[0]}(i,r,e.host,e._protocol)},s);return a.errorHandler=tu(t),a}(e.storage,e._location,te());return e.storage.makeRequestWithTokens(t,t_).then(e=>{if(null===e)throw new ex("no-download-url","The given file does not have any download URLs.");return e})}(e=(0,u.m9)(e))}delete(){var e;return this._throwIfRoot("delete"),e=this._delegate,function(e){e._throwIfRoot("deleteObject");let t=function(e,t){let n=t.fullServerUrl(),r=eK(n,e.host,e._protocol),i=e.maxOperationRetryTime,s=new ts(r,"DELETE",function(e,t){},i);return s.successCodes=[200,204],s.errorHandler=tu(t),s}(e.storage,e._location);return e.storage.makeRequestWithTokens(t,t_)}(e=(0,u.m9)(e))}_throwIfRoot(e){if(""===this._delegate._location.path)throw eF(e)}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class tL{constructor(e,t){this.app=e,this._delegate=t}get maxOperationRetryTime(){return this._delegate.maxOperationRetryTime}get maxUploadRetryTime(){return this._delegate.maxUploadRetryTime}ref(e){if(tM(e))throw eL("ref() expected a child path but got a URL, use refFromURL instead.");return new tP(tR(this._delegate,e),this)}refFromURL(e){if(!tM(e))throw eL("refFromURL() expected a full URL but got a child path, use ref() instead.");try{eq.makeFromUrl(e,this._delegate.host)}catch(t){throw eL("refFromUrl() expected a valid full URL but got an invalid one.")}return new tP(tR(this._delegate,e),this)}setMaxUploadRetryTime(e){this._delegate.maxUploadRetryTime=e}setMaxOperationRetryTime(e){this._delegate.maxOperationRetryTime=e}useEmulator(e,t,n={}){!function(e,t,n,r={}){!function(e,t,n,r={}){e.host=`${t}:${n}`,e._protocol="http";let{mockUserToken:i}=r;i&&(e._overrideAuthToken="string"==typeof i?i:(0,u.Sg)(i,e.app.options.projectId))}(e,t,n,r)}(this._delegate,e,t,n)}}function tM(e){return/^[A-Za-z]+:\/\//.test(e)}m.INTERNAL.registerComponent(new c.wA("storage-compat",function(e,{instanceIdentifier:t}){let n=e.getProvider("app-compat").getImmediate(),r=e.getProvider("storage").getImmediate({identifier:t}),i=new tL(n,r);return i},"PUBLIC").setServiceProps({TaskState:tp,TaskEvent:{STATE_CHANGED:"state_changed"},StringFormat:eJ,Storage:tL,Reference:tP}).setMultipleInstances(!0)),m.registerVersion("@firebase/storage-compat","0.2.0");var tF=n(6531);let tU="@firebase/installations",tV="0.6.0",tq=`w:${tV}`,tB="FIS_v2",tj=new u.LL("installations","Installations",{"missing-app-config-values":'Missing App configuration value: "{$valueName}"',"not-registered":"Firebase Installation is not registered.","installation-not-found":"Firebase Installation not found.","request-failed":'{$requestName} request failed with error "{$serverCode} {$serverStatus}: {$serverMessage}"',"app-offline":"Could not process request. Application offline.","delete-pending-registration":"Can't delete installation while there is a pending registration request."});function t$(e){return e instanceof u.ZR&&e.code.includes("request-failed")}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function tz({projectId:e}){return`https://firebaseinstallations.googleapis.com/v1/projects/${e}/installations`}function tG(e){return{token:e.token,requestStatus:2,expiresIn:Number(e.expiresIn.replace("s","000")),creationTime:Date.now()}}async function tK(e,t){let n=await t.json(),r=n.error;return tj.create("request-failed",{requestName:e,serverCode:r.code,serverMessage:r.message,serverStatus:r.status})}function tH({apiKey:e}){return new Headers({"Content-Type":"application/json",Accept:"application/json","x-goog-api-key":e})}async function tW(e){let t=await e();return t.status>=500&&t.status<600?e():t}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function tQ({appConfig:e,heartbeatServiceProvider:t},{fid:n}){let r=tz(e),i=tH(e),s=t.getImmediate({optional:!0});if(s){let a=await s.getHeartbeatsHeader();a&&i.append("x-firebase-client",a)}let o={fid:n,authVersion:tB,appId:e.appId,sdkVersion:tq},l={method:"POST",headers:i,body:JSON.stringify(o)},u=await tW(()=>fetch(r,l));if(u.ok){let c=await u.json(),h={fid:c.fid||n,registrationStatus:2,refreshToken:c.refreshToken,authToken:tG(c.authToken)};return h}throw await tK("Create Installation",u)}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function tY(e){return new Promise(t=>{setTimeout(t,e)})}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let tX=/^[cdef][\w-]{21}$/;/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function tJ(e){return`${e.appName}!${e.appId}`}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let tZ=new Map;function t0(e,t){let n=tJ(e);t1(n,t),function(e,t){let n=(!t2&&"BroadcastChannel"in self&&((t2=new BroadcastChannel("[Firebase] FID Change")).onmessage=e=>{t1(e.data.key,e.data.fid)}),t2);n&&n.postMessage({key:e,fid:t}),0===tZ.size&&t2&&(t2.close(),t2=null)}(n,t)}function t1(e,t){let n=tZ.get(e);if(n)for(let r of n)r(t)}let t2=null,t4="firebase-installations-store",t3=null;function t6(){return t3||(t3=(0,tF.X3)("firebase-installations-database",1,{upgrade:(e,t)=>{0===t&&e.createObjectStore(t4)}})),t3}async function t5(e,t){let n=tJ(e),r=await t6(),i=r.transaction(t4,"readwrite"),s=i.objectStore(t4),a=await s.get(n);return await s.put(t,n),await i.done,a&&a.fid===t.fid||t0(e,t.fid),t}async function t9(e){let t=tJ(e),n=await t6(),r=n.transaction(t4,"readwrite");await r.objectStore(t4).delete(t),await r.done}async function t8(e,t){let n=tJ(e),r=await t6(),i=r.transaction(t4,"readwrite"),s=i.objectStore(t4),a=await s.get(n),o=t(a);return void 0===o?await s.delete(n):await s.put(o,n),await i.done,o&&(!a||a.fid!==o.fid)&&t0(e,o.fid),o}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function t7(e){let t;let n=await t8(e.appConfig,n=>{let r=function(e){let t=e||{fid:function(){try{let e=new Uint8Array(17),t=self.crypto||self.msCrypto;t.getRandomValues(e),e[0]=112+e[0]%16;let n=function(e){let t=/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function(e){let t=btoa(String.fromCharCode(...e));return t.replace(/\+/g,"-").replace(/\//g,"_")}(e);return t.substr(0,22)}(e);return tX.test(n)?n:""}catch(r){return""}}(),registrationStatus:0};return nr(t)}(n),i=function(e,t){if(0===t.registrationStatus){if(!navigator.onLine){let n=Promise.reject(tj.create("app-offline"));return{installationEntry:t,registrationPromise:n}}let r={fid:t.fid,registrationStatus:1,registrationTime:Date.now()},i=ne(e,r);return{installationEntry:r,registrationPromise:i}}return 1===t.registrationStatus?{installationEntry:t,registrationPromise:nt(e)}:{installationEntry:t}}(e,r);return t=i.registrationPromise,i.installationEntry});return""===n.fid?{installationEntry:await t}:{installationEntry:n,registrationPromise:t}}async function ne(e,t){try{let n=await tQ(e,t);return t5(e.appConfig,n)}catch(r){throw t$(r)&&409===r.customData.serverCode?await t9(e.appConfig):await t5(e.appConfig,{fid:t.fid,registrationStatus:0}),r}}async function nt(e){let t=await nn(e.appConfig);for(;1===t.registrationStatus;)await tY(100),t=await nn(e.appConfig);if(0===t.registrationStatus){let{installationEntry:n,registrationPromise:r}=await t7(e);return r||n}return t}function nn(e){return t8(e,e=>{if(!e)throw tj.create("installation-not-found");return nr(e)})}function nr(e){return 1===e.registrationStatus&&e.registrationTime+1e4<Date.now()?{fid:e.fid,registrationStatus:0}:e}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function ni({appConfig:e,heartbeatServiceProvider:t},n){let r=function(e,{fid:t}){return`${tz(e)}/${t}/authTokens:generate`}(e,n),i=function(e,{refreshToken:t}){let n=tH(e);return n.append("Authorization",`${tB} ${t}`),n}(e,n),s=t.getImmediate({optional:!0});if(s){let a=await s.getHeartbeatsHeader();a&&i.append("x-firebase-client",a)}let o={installation:{sdkVersion:tq,appId:e.appId}},l={method:"POST",headers:i,body:JSON.stringify(o)},u=await tW(()=>fetch(r,l));if(u.ok){let c=await u.json(),h=tG(c);return h}throw await tK("Generate Auth Token",u)}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function ns(e,t=!1){let n;let r=await t8(e.appConfig,r=>{var i;if(!nu(r))throw tj.create("not-registered");let s=r.authToken;if(!t&&2===(i=s).requestStatus&&!function(e){let t=Date.now();return t<e.creationTime||e.creationTime+e.expiresIn<t+36e5}(i))return r;if(1===s.requestStatus)return n=na(e,t),r;{if(!navigator.onLine)throw tj.create("app-offline");let a=function(e){let t={requestStatus:1,requestTime:Date.now()};return Object.assign(Object.assign({},e),{authToken:t})}(r);return n=nl(e,a),a}}),i=n?await n:r.authToken;return i}async function na(e,t){let n=await no(e.appConfig);for(;1===n.authToken.requestStatus;)await tY(100),n=await no(e.appConfig);let r=n.authToken;return 0===r.requestStatus?ns(e,t):r}function no(e){return t8(e,e=>{if(!nu(e))throw tj.create("not-registered");let t=e.authToken;return 1===t.requestStatus&&t.requestTime+1e4<Date.now()?Object.assign(Object.assign({},e),{authToken:{requestStatus:0}}):e})}async function nl(e,t){try{let n=await ni(e,t),r=Object.assign(Object.assign({},t),{authToken:n});return await t5(e.appConfig,r),n}catch(s){if(t$(s)&&(401===s.customData.serverCode||404===s.customData.serverCode))await t9(e.appConfig);else{let i=Object.assign(Object.assign({},t),{authToken:{requestStatus:0}});await t5(e.appConfig,i)}throw s}}function nu(e){return void 0!==e&&2===e.registrationStatus}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function nc(e){let{installationEntry:t,registrationPromise:n}=await t7(e);return n?n.catch(console.error):ns(e).catch(console.error),t.fid}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function nh(e,t=!1){await nd(e);let n=await ns(e,t);return n.token}async function nd(e){let{registrationPromise:t}=await t7(e);t&&await t}function nf(e){return tj.create("missing-app-config-values",{valueName:e})}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let np="installations",nm=e=>{let t=e.getProvider("app").getImmediate(),n=/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function(e){if(!e||!e.options)throw nf("App Configuration");if(!e.name)throw nf("App Name");for(let t of["projectId","apiKey","appId"])if(!e.options[t])throw nf(t);return{appName:e.name,projectId:e.options.projectId,apiKey:e.options.apiKey,appId:e.options.appId}}(t),r=(0,h._getProvider)(t,"heartbeat");return{app:t,appConfig:n,heartbeatServiceProvider:r,_delete:()=>Promise.resolve()}},ng=e=>{let t=e.getProvider("app").getImmediate(),n=(0,h._getProvider)(t,np).getImmediate();return{getId:()=>nc(n),getToken:e=>nh(n,e)}};(0,h._registerComponent)(new c.wA(np,nm,"PUBLIC")),(0,h._registerComponent)(new c.wA("installations-internal",ng,"PRIVATE")),(0,h.registerVersion)(tU,tV),(0,h.registerVersion)(tU,tV,"esm2017");/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let ny="analytics",nv="https://www.googletagmanager.com/gtag/js",nw=new d.Yd("@firebase/analytics");/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */function n_(e){return Promise.all(e.map(e=>e.catch(e=>e)))}async function nb(e,t,n,r,i,s){let a=r[i];try{if(a)await t[a];else{let o=await n_(n),l=o.find(e=>e.measurementId===i);l&&await t[l.appId]}}catch(u){nw.error(u)}e("config",i,s)}async function nI(e,t,n,r,i){try{let s=[];if(i&&i.send_to){let a=i.send_to;Array.isArray(a)||(a=[a]);let o=await n_(n);for(let l of a){let u=o.find(e=>e.measurementId===l),c=u&&t[u.appId];if(c)s.push(c);else{s=[];break}}}0===s.length&&(s=Object.values(t)),await Promise.all(s),e("event",r,i||{})}catch(h){nw.error(h)}}let nT=new u.LL("analytics","Analytics",{"already-exists":"A Firebase Analytics instance with the appId {$id}  already exists. Only one Firebase Analytics instance can be created for each appId.","already-initialized":"initializeAnalytics() cannot be called again with different options than those it was initially called with. It can be called again with the same options to return the existing instance, or getAnalytics() can be used to get a reference to the already-intialized instance.","already-initialized-settings":"Firebase Analytics has already been initialized.settings() must be called before initializing any Analytics instanceor it will have no effect.","interop-component-reg-failed":"Firebase Analytics Interop Component failed to instantiate: {$reason}","invalid-analytics-context":"Firebase Analytics is not supported in this environment. Wrap initialization of analytics in analytics.isSupported() to prevent initialization in unsupported environments. Details: {$errorInfo}","indexeddb-unavailable":"IndexedDB unavailable or restricted in this environment. Wrap initialization of analytics in analytics.isSupported() to prevent initialization in unsupported environments. Details: {$errorInfo}","fetch-throttle":"The config fetch request timed out while in an exponential backoff state. Unix timestamp in milliseconds when fetch request throttling ends: {$throttleEndTimeMillis}.","config-fetch-failed":"Dynamic config fetch failed: [{$httpStatus}] {$responseMessage}","no-api-key":'The "apiKey" field is empty in the local Firebase config. Firebase Analytics requires this field tocontain a valid API key.',"no-app-id":'The "appId" field is empty in the local Firebase config. Firebase Analytics requires this field tocontain a valid app ID.'}),nE=new class{constructor(e={},t=1e3){this.throttleMetadata=e,this.intervalMillis=t}getThrottleMetadata(e){return this.throttleMetadata[e]}setThrottleMetadata(e,t){this.throttleMetadata[e]=t}deleteThrottleMetadata(e){delete this.throttleMetadata[e]}};async function nS(e){var t;let{appId:n,apiKey:r}=e,i={method:"GET",headers:new Headers({Accept:"application/json","x-goog-api-key":r})},s="https://firebase.googleapis.com/v1alpha/projects/-/apps/{app-id}/webConfig".replace("{app-id}",n),a=await fetch(s,i);if(200!==a.status&&304!==a.status){let o="";try{let l=await a.json();(null===(t=l.error)||void 0===t?void 0:t.message)&&(o=l.error.message)}catch(u){}throw nT.create("config-fetch-failed",{httpStatus:a.status,responseMessage:o})}return a.json()}async function nk(e,t=nE,n){let{appId:r,apiKey:i,measurementId:s}=e.options;if(!r)throw nT.create("no-app-id");if(!i){if(s)return{measurementId:s,appId:r};throw nT.create("no-api-key")}let a=t.getThrottleMetadata(r)||{backoffCount:0,throttleEndTimeMillis:Date.now()},o=new nC;return setTimeout(async()=>{o.abort()},void 0!==n?n:6e4),nA({appId:r,apiKey:i,measurementId:s},a,o,t)}async function nA(e,{throttleEndTimeMillis:t,backoffCount:n},r,i=nE){var s;let{appId:a,measurementId:o}=e;try{await new Promise((e,n)=>{let i=Math.max(t-Date.now(),0),s=setTimeout(e,i);r.addEventListener(()=>{clearTimeout(s),n(nT.create("fetch-throttle",{throttleEndTimeMillis:t}))})})}catch(l){if(o)return nw.warn(`Timed out fetching this Firebase app's measurement ID from the server. Falling back to the measurement ID ${o} provided in the "measurementId" field in the local Firebase config. [${null==l?void 0:l.message}]`),{appId:a,measurementId:o};throw l}try{let c=await nS(e);return i.deleteThrottleMetadata(a),c}catch(f){if(!function(e){if(!(e instanceof u.ZR)||!e.customData)return!1;let t=Number(e.customData.httpStatus);return 429===t||500===t||503===t||504===t}(f)){if(i.deleteThrottleMetadata(a),o)return nw.warn(`Failed to fetch this Firebase app's measurement ID from the server. Falling back to the measurement ID ${o} provided in the "measurementId" field in the local Firebase config. [${null==f?void 0:f.message}]`),{appId:a,measurementId:o};throw f}let h=503===Number(null===(s=null==f?void 0:f.customData)||void 0===s?void 0:s.httpStatus)?(0,u.$s)(n,i.intervalMillis,30):(0,u.$s)(n,i.intervalMillis),d={throttleEndTimeMillis:Date.now()+h,backoffCount:n+1};return i.setThrottleMetadata(a,d),nw.debug(`Calling attemptFetch again in ${h} millis`),nA(e,d,r,i)}}class nC{constructor(){this.listeners=[]}addEventListener(e){this.listeners.push(e)}abort(){this.listeners.forEach(e=>e())}}async function nx(e,t,n,r,i){if(i&&i.global){e("event",n,r);return}{let s=await t,a=Object.assign(Object.assign({},r),{send_to:s});e("event",n,a)}}/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */async function nR(){if(!(0,u.hl)())return nw.warn(nT.create("indexeddb-unavailable",{errorInfo:"IndexedDB is not available in this environment."}).message),!1;try{await (0,u.eu)()}catch(e){return nw.warn(nT.create("indexeddb-unavailable",{errorInfo:null==e?void 0:e.toString()}).message),!1}return!0}async function nD(e,t,n,s,a,o,l){var u;let c=nk(e);c.then(t=>{n[t.measurementId]=t.appId,e.options.measurementId&&t.measurementId!==e.options.measurementId&&nw.warn(`The measurement ID in the local Firebase config (${e.options.measurementId}) does not match the measurement ID fetched from the server (${t.measurementId}). To ensure analytics events are always sent to the correct Analytics property, update the measurement ID field in the local config or remove it from the local config.`)}).catch(e=>nw.error(e)),t.push(c);let h=nR().then(e=>e?s.getId():void 0),[d,f]=await Promise.all([c,h]);!function(e){let t=window.document.getElementsByTagName("script");for(let n of Object.values(t))if(n.src&&n.src.includes(nv)&&n.src.includes(e))return n;return null}(o)&&function(e,t){let n=document.createElement("script");n.src=`${nv}?l=${e}&id=${t}`,n.async=!0,document.head.appendChild(n)}(o,d.measurementId),i&&(a("consent","default",i),i=void 0),a("js",new Date);let p=null!==(u=null==l?void 0:l.config)&&void 0!==u?u:{};return p.origin="firebase",p.update=!0,null!=f&&(p.firebase_id=f),a("config",d.measurementId,p),r&&(a("set",r),r=void 0),d.measurementId}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class nN{constructor(e){this.app=e}_delete(){return delete nO[this.app.options.appId],Promise.resolve()}}let nO={},nP=[],nL={},nM="dataLayer",nF=!1,nU="@firebase/analytics",nV="0.9.0";(0,h._registerComponent)(new c.wA(ny,(e,{options:t})=>{let n=e.getProvider("app").getImmediate(),r=e.getProvider("installations-internal").getImmediate();return function(e,t,n){!function(){let e=[];if((0,u.ru)()&&e.push("This is a browser extension environment."),(0,u.zI)()||e.push("Cookies are not available."),e.length>0){let t=e.map((e,t)=>`(${t+1}) ${e}`).join(" "),n=nT.create("invalid-analytics-context",{errorInfo:t});nw.warn(n.message)}}();let r=e.options.appId;if(!r)throw nT.create("no-app-id");if(!e.options.apiKey){if(e.options.measurementId)nw.warn(`The "apiKey" field is empty in the local Firebase config. This is needed to fetch the latest measurement ID for this Firebase app. Falling back to the measurement ID ${e.options.measurementId} provided in the "measurementId" field in the local Firebase config.`);else throw nT.create("no-api-key")}if(null!=nO[r])throw nT.create("already-exists",{id:r});if(!nF){var i,o;let l,c;l=[],Array.isArray(window[nM])?l=window[nM]:window[nM]=l;let{wrappedGtag:h,gtagCore:d}=(i="gtag",c=function(...e){window[nM].push(arguments)},window[i]&&"function"==typeof window[i]&&(c=window[i]),window[i]=(o=c,async function(e,t,n){try{"event"===e?await nI(o,nO,nP,t,n):"config"===e?await nb(o,nO,nP,nL,t,n):"consent"===e?o("consent","update",n):o("set",t)}catch(r){nw.error(r)}}),{gtagCore:c,wrappedGtag:window[i]});a=h,s=d,nF=!0}nO[r]=nD(e,nP,nL,t,s,nM,n);let f=new nN(e);return f}(n,r,t)},"PUBLIC")),(0,h._registerComponent)(new c.wA("analytics-internal",function(e){try{let t=e.getProvider(ny).getImmediate();return{logEvent:(e,n,r)=>(function(e,t,n,r){nx(a,nO[(e=(0,u.m9)(e)).app.options.appId],t,n,r).catch(e=>nw.error(e))})(t,e,n,r)}}catch(n){throw nT.create("interop-component-reg-failed",{reason:n})}},"PRIVATE")),(0,h.registerVersion)(nU,nV),(0,h.registerVersion)(nU,nV,"esm2017"),m.apps.length||m.initializeApp({apiKey:"AIzaSyCny0fiBRc1_p-Z5SzNcYEGjwiSZ3Ksaik",authDomain:"nextfire-ba64f.firebaseapp.com",projectId:"nextfire-ba64f",storageBucket:"nextfire-ba64f.appspot.com",messagingSenderId:"448623557092",appId:"1:448623557092:web:ddbf8f04299ab582a12ff1",measurementId:"G-H1VGWPNWK6"});let nq=m.auth(),nB=new m.auth.GoogleAuthProvider,nj=m.firestore(),n$=m.storage(),nz=m.storage.TaskEvent.STATE_CHANGED,nG=m.firestore.Timestamp.fromMillis,nK=m.firestore.FieldValue.serverTimestamp,nH=m.firestore.FieldValue.increment},227:function(e,t){"use strict";Object.defineProperty(t,"__esModule",{value:!0}),t.getDomainLocale=function(e,t,n,r){return!1},("function"==typeof t.default||"object"==typeof t.default&&null!==t.default)&&void 0===t.default.__esModule&&(Object.defineProperty(t.default,"__esModule",{value:!0}),Object.assign(t.default,t),e.exports=t.default)},1551:function(e,t,n){"use strict";Object.defineProperty(t,"__esModule",{value:!0}),t.default=void 0;var r=n(2648).Z,i=n(7273).Z,s=r(n(7294)),a=n(1003),o=n(7795),l=n(4465),u=n(2692),c=n(8245),h=n(9246),d=n(227),f=n(3468);let p=new Set;function m(e,t,n,r){if(a.isLocalURL(t)){if(!r.bypassPrefetchedCheck){let i=void 0!==r.locale?r.locale:"locale"in e?e.locale:void 0,s=t+"%"+n+"%"+i;if(p.has(s))return;p.add(s)}Promise.resolve(e.prefetch(t,n,r)).catch(e=>{})}}function g(e){return"string"==typeof e?e:o.formatUrl(e)}let y=s.default.forwardRef(function(e,t){let n,r;let{href:o,as:p,children:y,prefetch:v,passHref:w,replace:_,shallow:b,scroll:I,locale:T,onClick:E,onMouseEnter:S,onTouchStart:k,legacyBehavior:A=!1}=e,C=i(e,["href","as","children","prefetch","passHref","replace","shallow","scroll","locale","onClick","onMouseEnter","onTouchStart","legacyBehavior"]);n=y,A&&("string"==typeof n||"number"==typeof n)&&(n=s.default.createElement("a",null,n));let x=!1!==v,R=s.default.useContext(u.RouterContext),D=s.default.useContext(c.AppRouterContext),N=null!=R?R:D,O=!R,{href:P,as:L}=s.default.useMemo(()=>{if(!R){let e=g(o);return{href:e,as:p?g(p):e}}let[t,n]=a.resolveHref(R,o,!0);return{href:t,as:p?a.resolveHref(R,p):n||t}},[R,o,p]),M=s.default.useRef(P),F=s.default.useRef(L);A&&(r=s.default.Children.only(n));let U=A?r&&"object"==typeof r&&r.ref:t,[V,q,B]=h.useIntersection({rootMargin:"200px"}),j=s.default.useCallback(e=>{(F.current!==L||M.current!==P)&&(B(),F.current=L,M.current=P),V(e),U&&("function"==typeof U?U(e):"object"==typeof U&&(U.current=e))},[L,U,P,B,V]);s.default.useEffect(()=>{N&&q&&x&&m(N,P,L,{locale:T})},[L,P,q,T,x,null==R?void 0:R.locale,N]);let $={ref:j,onClick(e){A||"function"!=typeof E||E(e),A&&r.props&&"function"==typeof r.props.onClick&&r.props.onClick(e),N&&!e.defaultPrevented&&function(e,t,n,r,i,o,l,u,c,h){let{nodeName:d}=e.currentTarget,f="A"===d.toUpperCase();if(f&&(function(e){let{target:t}=e.currentTarget;return t&&"_self"!==t||e.metaKey||e.ctrlKey||e.shiftKey||e.altKey||e.nativeEvent&&2===e.nativeEvent.which}(e)||!a.isLocalURL(n)))return;e.preventDefault();let p=()=>{"beforePopState"in t?t[i?"replace":"push"](n,r,{shallow:o,locale:u,scroll:l}):t[i?"replace":"push"](r||n,{forceOptimisticNavigation:!h})};c?s.default.startTransition(p):p()}(e,N,P,L,_,b,I,T,O,x)},onMouseEnter(e){A||"function"!=typeof S||S(e),A&&r.props&&"function"==typeof r.props.onMouseEnter&&r.props.onMouseEnter(e),N&&(x||!O)&&m(N,P,L,{locale:T,priority:!0,bypassPrefetchedCheck:!0})},onTouchStart(e){A||"function"!=typeof k||k(e),A&&r.props&&"function"==typeof r.props.onTouchStart&&r.props.onTouchStart(e),N&&(x||!O)&&m(N,P,L,{locale:T,priority:!0,bypassPrefetchedCheck:!0})}};if(!A||w||"a"===r.type&&!("href"in r.props)){let z=void 0!==T?T:null==R?void 0:R.locale,G=(null==R?void 0:R.isLocaleDomain)&&d.getDomainLocale(L,z,null==R?void 0:R.locales,null==R?void 0:R.domainLocales);$.href=G||f.addBasePath(l.addLocale(L,z,null==R?void 0:R.defaultLocale))}return A?s.default.cloneElement(r,$):s.default.createElement("a",Object.assign({},C,$),n)});t.default=y,("function"==typeof t.default||"object"==typeof t.default&&null!==t.default)&&void 0===t.default.__esModule&&(Object.defineProperty(t.default,"__esModule",{value:!0}),Object.assign(t.default,t),e.exports=t.default)},9246:function(e,t,n){"use strict";Object.defineProperty(t,"__esModule",{value:!0}),t.useIntersection=function(e){let{rootRef:t,rootMargin:n,disabled:l}=e,u=l||!s,[c,h]=r.useState(!1),[d,f]=r.useState(null);r.useEffect(()=>{if(s){if(!u&&!c&&d&&d.tagName){let e=function(e,t,n){let{id:r,observer:i,elements:s}=function(e){let t;let n={root:e.root||null,margin:e.rootMargin||""},r=o.find(e=>e.root===n.root&&e.margin===n.margin);if(r&&(t=a.get(r)))return t;let i=new Map,s=new IntersectionObserver(e=>{e.forEach(e=>{let t=i.get(e.target),n=e.isIntersecting||e.intersectionRatio>0;t&&n&&t(n)})},e);return t={id:n,observer:s,elements:i},o.push(n),a.set(n,t),t}(n);return s.set(e,t),i.observe(e),function(){if(s.delete(e),i.unobserve(e),0===s.size){i.disconnect(),a.delete(r);let t=o.findIndex(e=>e.root===r.root&&e.margin===r.margin);t>-1&&o.splice(t,1)}}}(d,e=>e&&h(e),{root:null==t?void 0:t.current,rootMargin:n});return e}}else if(!c){let r=i.requestIdleCallback(()=>h(!0));return()=>i.cancelIdleCallback(r)}},[d,u,n,t,c]);let p=r.useCallback(()=>{h(!1)},[]);return[f,c,p]};var r=n(7294),i=n(4686);let s="function"==typeof IntersectionObserver,a=new Map,o=[];("function"==typeof t.default||"object"==typeof t.default&&null!==t.default)&&void 0===t.default.__esModule&&(Object.defineProperty(t.default,"__esModule",{value:!0}),Object.assign(t.default,t),e.exports=t.default)},2224:function(e,t,n){"use strict";n.r(t),n.d(t,{default:function(){return y}});var r=n(5893);n(7475);var i=n(1664),s=n.n(i),a=n(7294),o=n(8059),l=n(26),u=n(1163);function c(){let{user:e,username:t}=(0,a.useContext)(o.S),n=(0,u.useRouter)(),i=()=>{l.I8.signOut(),n.reload()};return(0,r.jsx)("nav",{className:"navbar",children:(0,r.jsxs)("ul",{children:[(0,r.jsx)("li",{children:(0,r.jsx)(s(),{href:"/",children:(0,r.jsx)("button",{className:"btn-logo",children:"FEED"})})}),t&&(0,r.jsxs)(r.Fragment,{children:[(0,r.jsx)("li",{className:"push-left",children:(0,r.jsx)("button",{onClick:i,children:"Sign Out"})}),(0,r.jsx)("li",{children:(0,r.jsx)(s(),{href:"/admin",children:(0,r.jsx)("button",{className:"btn-blue",children:"Write Posts"})})}),(0,r.jsx)("li",{children:(0,r.jsx)(s(),{href:"/".concat(t),children:(0,r.jsx)("img",{src:null==e?void 0:e.photoURL})})})]}),!t&&(0,r.jsx)("li",{children:(0,r.jsx)(s(),{href:"/enter",children:(0,r.jsx)("button",{className:"btn-blue",children:"Log in"})})})]})})}var h=n(6501),d=n(5786);n(4444),n(2238),n(3333),n(8463);/*! *****************************************************************************
Copyright (c) Microsoft Corporation.

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
***************************************************************************** */var f=function(){return(f=Object.assign||function(e){for(var t,n=1,r=arguments.length;n<r;n++)for(var i in t=arguments[n])Object.prototype.hasOwnProperty.call(t,i)&&(e[i]=t[i]);return e}).apply(this,arguments)},p=function(e){return{loading:null==e,value:e}},m=function(e){var t=e?e():void 0,n=(0,a.useReducer)(function(e,t){switch(t.type){case"error":return f(f({},e),{error:t.error,loading:!1,value:void 0});case"reset":return p(t.defaultValue);case"value":return f(f({},e),{error:void 0,loading:!1,value:t.value});default:return e}},p(t)),r=n[0],i=n[1],s=(0,a.useCallback)(function(){i({type:"reset",defaultValue:e?e():void 0})},[e]),o=(0,a.useCallback)(function(e){i({type:"error",error:e})},[]),l=(0,a.useCallback)(function(e){i({type:"value",value:e})},[]);return(0,a.useMemo)(function(){return{error:r.error,loading:r.loading,reset:s,setError:o,setValue:l,value:r.value}},[r.error,r.loading,s,o,l,r.value])},g=function(e,t){var n=m(function(){return e.currentUser}),r=n.error,i=n.loading,s=n.setError,o=n.setValue,l=n.value;return(0,a.useEffect)(function(){var n=(0,d.v)(e,function(e){var n,r,i,a;return n=void 0,r=void 0,i=void 0,a=function(){return function(e,t){var n,r,i,s,a={label:0,sent:function(){if(1&i[0])throw i[1];return i[1]},trys:[],ops:[]};return s={next:o(0),throw:o(1),return:o(2)},"function"==typeof Symbol&&(s[Symbol.iterator]=function(){return this}),s;function o(s){return function(o){return function(s){if(n)throw TypeError("Generator is already executing.");for(;a;)try{if(n=1,r&&(i=2&s[0]?r.return:s[0]?r.throw||((i=r.return)&&i.call(r),0):r.next)&&!(i=i.call(r,s[1])).done)return i;switch(r=0,i&&(s=[2&s[0],i.value]),s[0]){case 0:case 1:i=s;break;case 4:return a.label++,{value:s[1],done:!1};case 5:a.label++,r=s[1],s=[0];continue;case 7:s=a.ops.pop(),a.trys.pop();continue;default:if(!(i=(i=a.trys).length>0&&i[i.length-1])&&(6===s[0]||2===s[0])){a=0;continue}if(3===s[0]&&(!i||s[1]>i[0]&&s[1]<i[3])){a.label=s[1];break}if(6===s[0]&&a.label<i[1]){a.label=i[1],i=s;break}if(i&&a.label<i[2]){a.label=i[2],a.ops.push(s);break}i[2]&&a.ops.pop(),a.trys.pop();continue}s=t.call(e,a)}catch(o){s=[6,o],r=0}finally{n=i=0}if(5&s[0])throw s[1];return{value:s[0]?s[1]:void 0,done:!0}}([s,o])}}}(this,function(n){switch(n.label){case 0:if(!(null==t?void 0:t.onUserChanged))return[3,4];n.label=1;case 1:return n.trys.push([1,3,,4]),[4,t.onUserChanged(e)];case 2:return n.sent(),[3,4];case 3:return s(n.sent()),[3,4];case 4:return o(e),[2]}})},new(i||(i=Promise))(function(e,t){function s(e){try{l(a.next(e))}catch(n){t(n)}}function o(e){try{l(a.throw(e))}catch(n){t(n)}}function l(t){var n;t.done?e(t.value):((n=t.value)instanceof i?n:new i(function(e){e(n)})).then(s,o)}l((a=a.apply(n,r||[])).next())})},s);return function(){n()}},[e]),[l,i,r]};function y(e){let{Component:t,pageProps:n}=e,i=function(){let[e]=g(l.I8),[t,n]=(0,a.useState)(null);return(0,a.useEffect)(()=>{let t;if(e){let r=l.RZ.collection("users").doc(e.uid);t=r.onSnapshot(e=>{var t;n(null===(t=e.data())||void 0===t?void 0:t.username)})}else n(null);return t},[e]),{user:e,username:t}}();return(0,r.jsx)(r.Fragment,{children:(0,r.jsxs)(o.S.Provider,{value:i,children:[(0,r.jsx)(c,{}),(0,r.jsx)(t,{...n}),(0,r.jsx)(h.x7,{})]})})}},7475:function(){},7663:function(e){!function(){var t={229:function(e){var t,n,r,i=e.exports={};function s(){throw Error("setTimeout has not been defined")}function a(){throw Error("clearTimeout has not been defined")}function o(e){if(t===setTimeout)return setTimeout(e,0);if((t===s||!t)&&setTimeout)return t=setTimeout,setTimeout(e,0);try{return t(e,0)}catch(r){try{return t.call(null,e,0)}catch(n){return t.call(this,e,0)}}}!function(){try{t="function"==typeof setTimeout?setTimeout:s}catch(e){t=s}try{n="function"==typeof clearTimeout?clearTimeout:a}catch(r){n=a}}();var l=[],u=!1,c=-1;function h(){u&&r&&(u=!1,r.length?l=r.concat(l):c=-1,l.length&&d())}function d(){if(!u){var e=o(h);u=!0;for(var t=l.length;t;){for(r=l,l=[];++c<t;)r&&r[c].run();c=-1,t=l.length}r=null,u=!1,function(e){if(n===clearTimeout)return clearTimeout(e);if((n===a||!n)&&clearTimeout)return n=clearTimeout,clearTimeout(e);try{n(e)}catch(r){try{return n.call(null,e)}catch(t){return n.call(this,e)}}}(e)}}function f(e,t){this.fun=e,this.array=t}function p(){}i.nextTick=function(e){var t=Array(arguments.length-1);if(arguments.length>1)for(var n=1;n<arguments.length;n++)t[n-1]=arguments[n];l.push(new f(e,t)),1!==l.length||u||o(d)},f.prototype.run=function(){this.fun.apply(null,this.array)},i.title="browser",i.browser=!0,i.env={},i.argv=[],i.version="",i.versions={},i.on=p,i.addListener=p,i.once=p,i.off=p,i.removeListener=p,i.removeAllListeners=p,i.emit=p,i.prependListener=p,i.prependOnceListener=p,i.listeners=function(e){return[]},i.binding=function(e){throw Error("process.binding is not supported")},i.cwd=function(){return"/"},i.chdir=function(e){throw Error("process.chdir is not supported")},i.umask=function(){return 0}}},n={};function r(e){var i=n[e];if(void 0!==i)return i.exports;var s=n[e]={exports:{}},a=!0;try{t[e](s,s.exports,r),a=!1}finally{a&&delete n[e]}return s.exports}r.ab="//";var i=r(229);e.exports=i}()},1664:function(e,t,n){e.exports=n(1551)},1163:function(e,t,n){e.exports=n(880)},2238:function(e,t,n){"use strict";n.r(t),n.d(t,{FirebaseError:function(){return s.ZR},SDK_VERSION:function(){return T},_DEFAULT_ENTRY_NAME:function(){return h},_addComponent:function(){return m},_addOrOverwriteComponent:function(){return g},_apps:function(){return f},_clearComponents:function(){return _},_components:function(){return p},_getProvider:function(){return v},_registerComponent:function(){return y},_removeServiceInstance:function(){return w},deleteApp:function(){return A},getApp:function(){return S},getApps:function(){return k},initializeApp:function(){return E},onLog:function(){return x},registerVersion:function(){return C},setLogLevel:function(){return R}});var r=n(8463),i=n(3333),s=n(4444),a=n(6531);/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class o{constructor(e){this.container=e}getPlatformInfoString(){let e=this.container.getProviders();return e.map(e=>{if(!function(e){let t=e.getComponent();return(null==t?void 0:t.type)==="VERSION"}(e))return null;{let t=e.getImmediate();return`${t.library}/${t.version}`}}).filter(e=>e).join(" ")}}let l="@firebase/app",u="0.9.0",c=new i.Yd("@firebase/app"),h="[DEFAULT]",d={[l]:"fire-core","@firebase/app-compat":"fire-core-compat","@firebase/analytics":"fire-analytics","@firebase/analytics-compat":"fire-analytics-compat","@firebase/app-check":"fire-app-check","@firebase/app-check-compat":"fire-app-check-compat","@firebase/auth":"fire-auth","@firebase/auth-compat":"fire-auth-compat","@firebase/database":"fire-rtdb","@firebase/database-compat":"fire-rtdb-compat","@firebase/functions":"fire-fn","@firebase/functions-compat":"fire-fn-compat","@firebase/installations":"fire-iid","@firebase/installations-compat":"fire-iid-compat","@firebase/messaging":"fire-fcm","@firebase/messaging-compat":"fire-fcm-compat","@firebase/performance":"fire-perf","@firebase/performance-compat":"fire-perf-compat","@firebase/remote-config":"fire-rc","@firebase/remote-config-compat":"fire-rc-compat","@firebase/storage":"fire-gcs","@firebase/storage-compat":"fire-gcs-compat","@firebase/firestore":"fire-fst","@firebase/firestore-compat":"fire-fst-compat","fire-js":"fire-js",firebase:"fire-js-all"},f=new Map,p=new Map;function m(e,t){try{e.container.addComponent(t)}catch(n){c.debug(`Component ${t.name} failed to register with FirebaseApp ${e.name}`,n)}}function g(e,t){e.container.addOrOverwriteComponent(t)}function y(e){let t=e.name;if(p.has(t))return c.debug(`There were multiple attempts to register component ${t}.`),!1;for(let n of(p.set(t,e),f.values()))m(n,e);return!0}function v(e,t){let n=e.container.getProvider("heartbeat").getImmediate({optional:!0});return n&&n.triggerHeartbeat(),e.container.getProvider(t)}function w(e,t,n=h){v(e,t).clearInstance(n)}function _(){p.clear()}let b=new s.LL("app","Firebase",{"no-app":"No Firebase App '{$appName}' has been created - call Firebase App.initializeApp()","bad-app-name":"Illegal App name: '{$appName}","duplicate-app":"Firebase App named '{$appName}' already exists with different options or config","app-deleted":"Firebase App named '{$appName}' already deleted","no-options":"Need to provide options, when not being deployed to hosting via source.","invalid-app-argument":"firebase.{$appName}() takes either no argument or a Firebase App instance.","invalid-log-argument":"First argument to `onLog` must be null or a function.","idb-open":"Error thrown when opening IndexedDB. Original error: {$originalErrorMessage}.","idb-get":"Error thrown when reading from IndexedDB. Original error: {$originalErrorMessage}.","idb-set":"Error thrown when writing to IndexedDB. Original error: {$originalErrorMessage}.","idb-delete":"Error thrown when deleting from IndexedDB. Original error: {$originalErrorMessage}."});/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class I{constructor(e,t,n){this._isDeleted=!1,this._options=Object.assign({},e),this._config=Object.assign({},t),this._name=t.name,this._automaticDataCollectionEnabled=t.automaticDataCollectionEnabled,this._container=n,this.container.addComponent(new r.wA("app",()=>this,"PUBLIC"))}get automaticDataCollectionEnabled(){return this.checkDestroyed(),this._automaticDataCollectionEnabled}set automaticDataCollectionEnabled(e){this.checkDestroyed(),this._automaticDataCollectionEnabled=e}get name(){return this.checkDestroyed(),this._name}get options(){return this.checkDestroyed(),this._options}get config(){return this.checkDestroyed(),this._config}get container(){return this._container}get isDeleted(){return this._isDeleted}set isDeleted(e){this._isDeleted=e}checkDestroyed(){if(this.isDeleted)throw b.create("app-deleted",{appName:this._name})}}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let T="9.15.0";function E(e,t={}){let n=e;if("object"!=typeof t){let i=t;t={name:i}}let a=Object.assign({name:h,automaticDataCollectionEnabled:!1},t),o=a.name;if("string"!=typeof o||!o)throw b.create("bad-app-name",{appName:String(o)});if(n||(n=(0,s.aH)()),!n)throw b.create("no-options");let l=f.get(o);if(l){if((0,s.vZ)(n,l.options)&&(0,s.vZ)(a,l.config))return l;throw b.create("duplicate-app",{appName:o})}let u=new r.H0(o);for(let c of p.values())u.addComponent(c);let d=new I(n,a,u);return f.set(o,d),d}function S(e=h){let t=f.get(e);if(!t&&e===h)return E();if(!t)throw b.create("no-app",{appName:e});return t}function k(){return Array.from(f.values())}async function A(e){let t=e.name;f.has(t)&&(f.delete(t),await Promise.all(e.container.getProviders().map(e=>e.delete())),e.isDeleted=!0)}function C(e,t,n){var i;let s=null!==(i=d[e])&&void 0!==i?i:e;n&&(s+=`-${n}`);let a=s.match(/\s|\//),o=t.match(/\s|\//);if(a||o){let l=[`Unable to register library "${s}" with version "${t}":`];a&&l.push(`library name "${s}" contains illegal characters (whitespace or "/")`),a&&o&&l.push("and"),o&&l.push(`version name "${t}" contains illegal characters (whitespace or "/")`),c.warn(l.join(" "));return}y(new r.wA(`${s}-version`,()=>({library:s,version:t}),"VERSION"))}function x(e,t){if(null!==e&&"function"!=typeof e)throw b.create("invalid-log-argument");(0,i.Am)(e,t)}function R(e){(0,i.Ub)(e)}let D="firebase-heartbeat-store",N=null;function O(){return N||(N=(0,a.X3)("firebase-heartbeat-database",1,{upgrade:(e,t)=>{0===t&&e.createObjectStore(D)}}).catch(e=>{throw b.create("idb-open",{originalErrorMessage:e.message})})),N}async function P(e){try{let t=await O();return t.transaction(D).objectStore(D).get(M(e))}catch(r){if(r instanceof s.ZR)c.warn(r.message);else{let n=b.create("idb-get",{originalErrorMessage:null==r?void 0:r.message});c.warn(n.message)}}}async function L(e,t){try{let n=await O(),r=n.transaction(D,"readwrite"),i=r.objectStore(D);return await i.put(t,M(e)),r.done}catch(o){if(o instanceof s.ZR)c.warn(o.message);else{let a=b.create("idb-set",{originalErrorMessage:null==o?void 0:o.message});c.warn(a.message)}}}function M(e){return`${e.name}!${e.options.appId}`}class F{constructor(e){this.container=e,this._heartbeatsCache=null;let t=this.container.getProvider("app").getImmediate();this._storage=new V(t),this._heartbeatsCachePromise=this._storage.read().then(e=>(this._heartbeatsCache=e,e))}async triggerHeartbeat(){let e=this.container.getProvider("platform-logger").getImmediate(),t=e.getPlatformInfoString(),n=U();return(null===this._heartbeatsCache&&(this._heartbeatsCache=await this._heartbeatsCachePromise),this._heartbeatsCache.lastSentHeartbeatDate===n||this._heartbeatsCache.heartbeats.some(e=>e.date===n))?void 0:(this._heartbeatsCache.heartbeats.push({date:n,agent:t}),this._heartbeatsCache.heartbeats=this._heartbeatsCache.heartbeats.filter(e=>{let t=new Date(e.date).valueOf(),n=Date.now();return n-t<=2592e6}),this._storage.overwrite(this._heartbeatsCache))}async getHeartbeatsHeader(){if(null===this._heartbeatsCache&&await this._heartbeatsCachePromise,null===this._heartbeatsCache||0===this._heartbeatsCache.heartbeats.length)return"";let e=U(),{heartbeatsToSend:t,unsentEntries:n}=function(e,t=1024){let n=[],r=e.slice();for(let i of e){let s=n.find(e=>e.agent===i.agent);if(s){if(s.dates.push(i.date),q(n)>t){s.dates.pop();break}}else if(n.push({agent:i.agent,dates:[i.date]}),q(n)>t){n.pop();break}r=r.slice(1)}return{heartbeatsToSend:n,unsentEntries:r}}(this._heartbeatsCache.heartbeats),r=(0,s.L)(JSON.stringify({version:2,heartbeats:t}));return this._heartbeatsCache.lastSentHeartbeatDate=e,n.length>0?(this._heartbeatsCache.heartbeats=n,await this._storage.overwrite(this._heartbeatsCache)):(this._heartbeatsCache.heartbeats=[],this._storage.overwrite(this._heartbeatsCache)),r}}function U(){let e=new Date;return e.toISOString().substring(0,10)}class V{constructor(e){this.app=e,this._canUseIndexedDBPromise=this.runIndexedDBEnvironmentCheck()}async runIndexedDBEnvironmentCheck(){return!!(0,s.hl)()&&(0,s.eu)().then(()=>!0).catch(()=>!1)}async read(){let e=await this._canUseIndexedDBPromise;if(!e)return{heartbeats:[]};{let t=await P(this.app);return t||{heartbeats:[]}}}async overwrite(e){var t;let n=await this._canUseIndexedDBPromise;if(n){let r=await this.read();return L(this.app,{lastSentHeartbeatDate:null!==(t=e.lastSentHeartbeatDate)&&void 0!==t?t:r.lastSentHeartbeatDate,heartbeats:e.heartbeats})}}async add(e){var t;let n=await this._canUseIndexedDBPromise;if(n){let r=await this.read();return L(this.app,{lastSentHeartbeatDate:null!==(t=e.lastSentHeartbeatDate)&&void 0!==t?t:r.lastSentHeartbeatDate,heartbeats:[...r.heartbeats,...e.heartbeats]})}}}function q(e){return(0,s.L)(JSON.stringify({version:2,heartbeats:e})).length}y(new r.wA("platform-logger",e=>new o(e),"PRIVATE")),y(new r.wA("heartbeat",e=>new F(e),"PRIVATE")),C(l,u,""),C(l,u,"esm2017"),C("fire-js","")},8463:function(e,t,n){"use strict";n.d(t,{H0:function(){return o},wA:function(){return i}});var r=n(4444);class i{constructor(e,t,n){this.name=e,this.instanceFactory=t,this.type=n,this.multipleInstances=!1,this.serviceProps={},this.instantiationMode="LAZY",this.onInstanceCreated=null}setInstantiationMode(e){return this.instantiationMode=e,this}setMultipleInstances(e){return this.multipleInstances=e,this}setServiceProps(e){return this.serviceProps=e,this}setInstanceCreatedCallback(e){return this.onInstanceCreated=e,this}}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let s="[DEFAULT]";/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class a{constructor(e,t){this.name=e,this.container=t,this.component=null,this.instances=new Map,this.instancesDeferred=new Map,this.instancesOptions=new Map,this.onInitCallbacks=new Map}get(e){let t=this.normalizeInstanceIdentifier(e);if(!this.instancesDeferred.has(t)){let n=new r.BH;if(this.instancesDeferred.set(t,n),this.isInitialized(t)||this.shouldAutoInitialize())try{let i=this.getOrInitializeService({instanceIdentifier:t});i&&n.resolve(i)}catch(s){}}return this.instancesDeferred.get(t).promise}getImmediate(e){var t;let n=this.normalizeInstanceIdentifier(null==e?void 0:e.identifier),r=null!==(t=null==e?void 0:e.optional)&&void 0!==t&&t;if(this.isInitialized(n)||this.shouldAutoInitialize())try{return this.getOrInitializeService({instanceIdentifier:n})}catch(i){if(r)return null;throw i}else{if(r)return null;throw Error(`Service ${this.name} is not available`)}}getComponent(){return this.component}setComponent(e){if(e.name!==this.name)throw Error(`Mismatching Component ${e.name} for Provider ${this.name}.`);if(this.component)throw Error(`Component for ${this.name} has already been provided`);if(this.component=e,this.shouldAutoInitialize()){if("EAGER"===e.instantiationMode)try{this.getOrInitializeService({instanceIdentifier:s})}catch(t){}for(let[n,r]of this.instancesDeferred.entries()){let i=this.normalizeInstanceIdentifier(n);try{let a=this.getOrInitializeService({instanceIdentifier:i});r.resolve(a)}catch(o){}}}}clearInstance(e=s){this.instancesDeferred.delete(e),this.instancesOptions.delete(e),this.instances.delete(e)}async delete(){let e=Array.from(this.instances.values());await Promise.all([...e.filter(e=>"INTERNAL"in e).map(e=>e.INTERNAL.delete()),...e.filter(e=>"_delete"in e).map(e=>e._delete())])}isComponentSet(){return null!=this.component}isInitialized(e=s){return this.instances.has(e)}getOptions(e=s){return this.instancesOptions.get(e)||{}}initialize(e={}){let{options:t={}}=e,n=this.normalizeInstanceIdentifier(e.instanceIdentifier);if(this.isInitialized(n))throw Error(`${this.name}(${n}) has already been initialized`);if(!this.isComponentSet())throw Error(`Component ${this.name} has not been registered yet`);let r=this.getOrInitializeService({instanceIdentifier:n,options:t});for(let[i,s]of this.instancesDeferred.entries()){let a=this.normalizeInstanceIdentifier(i);n===a&&s.resolve(r)}return r}onInit(e,t){var n;let r=this.normalizeInstanceIdentifier(t),i=null!==(n=this.onInitCallbacks.get(r))&&void 0!==n?n:new Set;i.add(e),this.onInitCallbacks.set(r,i);let s=this.instances.get(r);return s&&e(s,r),()=>{i.delete(e)}}invokeOnInitCallbacks(e,t){let n=this.onInitCallbacks.get(t);if(n)for(let r of n)try{r(e,t)}catch(i){}}getOrInitializeService({instanceIdentifier:e,options:t={}}){let n=this.instances.get(e);if(!n&&this.component&&(n=this.component.instanceFactory(this.container,{instanceIdentifier:e===s?void 0:e,options:t}),this.instances.set(e,n),this.instancesOptions.set(e,t),this.invokeOnInitCallbacks(n,e),this.component.onInstanceCreated))try{this.component.onInstanceCreated(this.container,e,n)}catch(r){}return n||null}normalizeInstanceIdentifier(e=s){return this.component?this.component.multipleInstances?e:s:e}shouldAutoInitialize(){return!!this.component&&"EXPLICIT"!==this.component.instantiationMode}}/**
 * @license
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */class o{constructor(e){this.name=e,this.providers=new Map}addComponent(e){let t=this.getProvider(e.name);if(t.isComponentSet())throw Error(`Component ${e.name} has already been registered with ${this.name}`);t.setComponent(e)}addOrOverwriteComponent(e){let t=this.getProvider(e.name);t.isComponentSet()&&this.providers.delete(e.name),this.addComponent(e)}getProvider(e){if(this.providers.has(e))return this.providers.get(e);let t=new a(e,this);return this.providers.set(e,t),t}getProviders(){return Array.from(this.providers.values())}}},3333:function(e,t,n){"use strict";var r,i;n.d(t,{Am:function(){return d},Ub:function(){return h},Yd:function(){return c},in:function(){return r}});/**
 * @license
 * Copyright 2017 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */let s=[];(i=r||(r={}))[i.DEBUG=0]="DEBUG",i[i.VERBOSE=1]="VERBOSE",i[i.INFO=2]="INFO",i[i.WARN=3]="WARN",i[i.ERROR=4]="ERROR",i[i.SILENT=5]="SILENT";let a={debug:r.DEBUG,verbose:r.VERBOSE,info:r.INFO,warn:r.WARN,error:r.ERROR,silent:r.SILENT},o=r.INFO,l={[r.DEBUG]:"log",[r.VERBOSE]:"log",[r.INFO]:"info",[r.WARN]:"warn",[r.ERROR]:"error"},u=(e,t,...n)=>{if(t<e.logLevel)return;let r=new Date().toISOString(),i=l[t];if(i)console[i](`[${r}]  ${e.name}:`,...n);else throw Error(`Attempted to log a message with an invalid logType (value: ${t})`)};class c{constructor(e){this.name=e,this._logLevel=o,this._logHandler=u,this._userLogHandler=null,s.push(this)}get logLevel(){return this._logLevel}set logLevel(e){if(!(e in r))throw TypeError(`Invalid value "${e}" assigned to \`logLevel\``);this._logLevel=e}setLogLevel(e){this._logLevel="string"==typeof e?a[e]:e}get logHandler(){return this._logHandler}set logHandler(e){if("function"!=typeof e)throw TypeError("Value assigned to `logHandler` must be a function");this._logHandler=e}get userLogHandler(){return this._userLogHandler}set userLogHandler(e){this._userLogHandler=e}debug(...e){this._userLogHandler&&this._userLogHandler(this,r.DEBUG,...e),this._logHandler(this,r.DEBUG,...e)}log(...e){this._userLogHandler&&this._userLogHandler(this,r.VERBOSE,...e),this._logHandler(this,r.VERBOSE,...e)}info(...e){this._userLogHandler&&this._userLogHandler(this,r.INFO,...e),this._logHandler(this,r.INFO,...e)}warn(...e){this._userLogHandler&&this._userLogHandler(this,r.WARN,...e),this._logHandler(this,r.WARN,...e)}error(...e){this._userLogHandler&&this._userLogHandler(this,r.ERROR,...e),this._logHandler(this,r.ERROR,...e)}}function h(e){s.forEach(t=>{t.setLogLevel(e)})}function d(e,t){for(let n of s){let i=null;t&&t.level&&(i=a[t.level]),null===e?n.userLogHandler=null:n.userLogHandler=(t,n,...s)=>{let a=s.map(e=>{if(null==e)return null;if("string"==typeof e)return e;if("number"==typeof e||"boolean"==typeof e)return e.toString();if(e instanceof Error)return e.message;try{return JSON.stringify(e)}catch(t){return null}}).filter(e=>e).join(" ");n>=(null!=i?i:t.logLevel)&&e({level:r[n].toLowerCase(),message:a,args:s,type:t.name})}}}},6531:function(e,t,n){"use strict";var r;let i,s;n.d(t,{X3:function(){return m}});let a=(e,t)=>t.some(t=>e instanceof t),o=new WeakMap,l=new WeakMap,u=new WeakMap,c=new WeakMap,h=new WeakMap,d={get(e,t,n){if(e instanceof IDBTransaction){if("done"===t)return l.get(e);if("objectStoreNames"===t)return e.objectStoreNames||u.get(e);if("store"===t)return n.objectStoreNames[1]?void 0:n.objectStore(n.objectStoreNames[0])}return f(e[t])},set:(e,t,n)=>(e[t]=n,!0),has:(e,t)=>e instanceof IDBTransaction&&("done"===t||"store"===t)||t in e};function f(e){var t;if(e instanceof IDBRequest)return function(e){let t=new Promise((t,n)=>{let r=()=>{e.removeEventListener("success",i),e.removeEventListener("error",s)},i=()=>{t(f(e.result)),r()},s=()=>{n(e.error),r()};e.addEventListener("success",i),e.addEventListener("error",s)});return t.then(t=>{t instanceof IDBCursor&&o.set(t,e)}).catch(()=>{}),h.set(t,e),t}(e);if(c.has(e))return c.get(e);let n="function"==typeof(t=e)?t!==IDBDatabase.prototype.transaction||"objectStoreNames"in IDBTransaction.prototype?(s||(s=[IDBCursor.prototype.advance,IDBCursor.prototype.continue,IDBCursor.prototype.continuePrimaryKey])).includes(t)?function(...e){return t.apply(p(this),e),f(o.get(this))}:function(...e){return f(t.apply(p(this),e))}:function(e,...n){let r=t.call(p(this),e,...n);return u.set(r,e.sort?e.sort():[e]),f(r)}:(t instanceof IDBTransaction&&function(e){if(l.has(e))return;let t=new Promise((t,n)=>{let r=()=>{e.removeEventListener("complete",i),e.removeEventListener("error",s),e.removeEventListener("abort",s)},i=()=>{t(),r()},s=()=>{n(e.error||new DOMException("AbortError","AbortError")),r()};e.addEventListener("complete",i),e.addEventListener("error",s),e.addEventListener("abort",s)});l.set(e,t)}(t),a(t,i||(i=[IDBDatabase,IDBObjectStore,IDBIndex,IDBCursor,IDBTransaction])))?new Proxy(t,d):t;return n!==e&&(c.set(e,n),h.set(n,e)),n}let p=e=>h.get(e);function m(e,t,{blocked:n,upgrade:r,blocking:i,terminated:s}={}){let a=indexedDB.open(e,t),o=f(a);return r&&a.addEventListener("upgradeneeded",e=>{r(f(a.result),e.oldVersion,e.newVersion,f(a.transaction))}),n&&a.addEventListener("blocked",()=>n()),o.then(e=>{s&&e.addEventListener("close",()=>s()),i&&e.addEventListener("versionchange",()=>i())}).catch(()=>{}),o}let g=["get","getKey","getAll","getAllKeys","count"],y=["put","add","delete","clear"],v=new Map;function w(e,t){if(!(e instanceof IDBDatabase&&!(t in e)&&"string"==typeof t))return;if(v.get(t))return v.get(t);let n=t.replace(/FromIndex$/,""),r=t!==n,i=y.includes(n);if(!(n in(r?IDBIndex:IDBObjectStore).prototype)||!(i||g.includes(n)))return;let s=async function(e,...t){let s=this.transaction(e,i?"readwrite":"readonly"),a=s.store;return r&&(a=a.index(t.shift())),(await Promise.all([a[n](...t),i&&s.done]))[0]};return v.set(t,s),s}d={...r=d,get:(e,t,n)=>w(e,t)||r.get(e,t,n),has:(e,t)=>!!w(e,t)||r.has(e,t)}},6501:function(e,t,n){"use strict";let r,i;n.d(t,{x7:function(){return ei},ZP:function(){return es}});var s,a=n(7294);let o={data:""},l=e=>"object"==typeof window?((e?e.querySelector("#_goober"):window._goober)||Object.assign((e||document.head).appendChild(document.createElement("style")),{innerHTML:" ",id:"_goober"})).firstChild:e||o,u=/(?:([\u0080-\uFFFF\w-%@]+) *:? *([^{;]+?);|([^;}{]*?) *{)|(}\s*)/g,c=/\/\*[^]*?\*\/|  +/g,h=/\n+/g,d=(e,t)=>{let n="",r="",i="";for(let s in e){let a=e[s];"@"==s[0]?"i"==s[1]?n=s+" "+a+";":r+="f"==s[1]?d(a,s):s+"{"+d(a,"k"==s[1]?"":t)+"}":"object"==typeof a?r+=d(a,t?t.replace(/([^,])+/g,e=>s.replace(/(^:.*)|([^,])+/g,t=>/&/.test(t)?t.replace(/&/g,e):e?e+" "+t:t)):s):null!=a&&(s=/^--/.test(s)?s:s.replace(/[A-Z]/g,"-$&").toLowerCase(),i+=d.p?d.p(s,a):s+":"+a+";")}return n+(t&&i?t+"{"+i+"}":i)+r},f={},p=e=>{if("object"==typeof e){let t="";for(let n in e)t+=n+p(e[n]);return t}return e},m=(e,t,n,r,i)=>{var s,a;let o=p(e),l=f[o]||(f[o]=(e=>{let t=0,n=11;for(;t<e.length;)n=101*n+e.charCodeAt(t++)>>>0;return"go"+n})(o));if(!f[l]){let m=o!==e?e:(e=>{let t,n,r=[{}];for(;t=u.exec(e.replace(c,""));)t[4]?r.shift():t[3]?(n=t[3].replace(h," ").trim(),r.unshift(r[0][n]=r[0][n]||{})):r[0][t[1]]=t[2].replace(h," ").trim();return r[0]})(e);f[l]=d(i?{["@keyframes "+l]:m}:m,n?"":"."+l)}let g=n&&f.g?f.g:null;return n&&(f.g=f[l]),s=f[l],a=t,g?a.data=a.data.replace(g,s):-1===a.data.indexOf(s)&&(a.data=r?s+a.data:a.data+s),l},g=(e,t,n)=>e.reduce((e,r,i)=>{let s=t[i];if(s&&s.call){let a=s(n),o=a&&a.props&&a.props.className||/^go/.test(a)&&a;s=o?"."+o:a&&"object"==typeof a?a.props?"":d(a,""):!1===a?"":a}return e+r+(null==s?"":s)},"");function y(e){let t=this||{},n=e.call?e(t.p):e;return m(n.unshift?n.raw?g(n,[].slice.call(arguments,1),t.p):n.reduce((e,n)=>Object.assign(e,n&&n.call?n(t.p):n),{}):n,l(t.target),t.g,t.o,t.k)}y.bind({g:1});let v,w,_,b=y.bind({k:1});function I(e,t){let n=this||{};return function(){let r=arguments;function i(s,a){let o=Object.assign({},s),l=o.className||i.className;n.p=Object.assign({theme:w&&w()},o),n.o=/ *go\d+/.test(l),o.className=y.apply(n,r)+(l?" "+l:""),t&&(o.ref=a);let u=e;return e[0]&&(u=o.as||e,delete o.as),_&&u[0]&&_(o),v(u,o)}return t?t(i):i}}var T=e=>"function"==typeof e,E=(e,t)=>T(e)?e(t):e,S=(r=0,()=>(++r).toString()),k=()=>{if(void 0===i&&"u">typeof window){let e=matchMedia("(prefers-reduced-motion: reduce)");i=!e||e.matches}return i},A=new Map,C=e=>{if(A.has(e))return;let t=setTimeout(()=>{A.delete(e),O({type:4,toastId:e})},1e3);A.set(e,t)},x=e=>{let t=A.get(e);t&&clearTimeout(t)},R=(e,t)=>{switch(t.type){case 0:return{...e,toasts:[t.toast,...e.toasts].slice(0,20)};case 1:return t.toast.id&&x(t.toast.id),{...e,toasts:e.toasts.map(e=>e.id===t.toast.id?{...e,...t.toast}:e)};case 2:let{toast:n}=t;return e.toasts.find(e=>e.id===n.id)?R(e,{type:1,toast:n}):R(e,{type:0,toast:n});case 3:let{toastId:r}=t;return r?C(r):e.toasts.forEach(e=>{C(e.id)}),{...e,toasts:e.toasts.map(e=>e.id===r||void 0===r?{...e,visible:!1}:e)};case 4:return void 0===t.toastId?{...e,toasts:[]}:{...e,toasts:e.toasts.filter(e=>e.id!==t.toastId)};case 5:return{...e,pausedAt:t.time};case 6:let i=t.time-(e.pausedAt||0);return{...e,pausedAt:void 0,toasts:e.toasts.map(e=>({...e,pauseDuration:e.pauseDuration+i}))}}},D=[],N={toasts:[],pausedAt:void 0},O=e=>{N=R(N,e),D.forEach(e=>{e(N)})},P={blank:4e3,error:4e3,success:2e3,loading:1/0,custom:4e3},L=(e={})=>{let[t,n]=(0,a.useState)(N);(0,a.useEffect)(()=>(D.push(n),()=>{let e=D.indexOf(n);e>-1&&D.splice(e,1)}),[t]);let r=t.toasts.map(t=>{var n,r;return{...e,...e[t.type],...t,duration:t.duration||(null==(n=e[t.type])?void 0:n.duration)||(null==e?void 0:e.duration)||P[t.type],style:{...e.style,...null==(r=e[t.type])?void 0:r.style,...t.style}}});return{...t,toasts:r}},M=(e,t="blank",n)=>({createdAt:Date.now(),visible:!0,type:t,ariaProps:{role:"status","aria-live":"polite"},message:e,pauseDuration:0,...n,id:(null==n?void 0:n.id)||S()}),F=e=>(t,n)=>{let r=M(t,e,n);return O({type:2,toast:r}),r.id},U=(e,t)=>F("blank")(e,t);U.error=F("error"),U.success=F("success"),U.loading=F("loading"),U.custom=F("custom"),U.dismiss=e=>{O({type:3,toastId:e})},U.remove=e=>O({type:4,toastId:e}),U.promise=(e,t,n)=>{let r=U.loading(t.loading,{...n,...null==n?void 0:n.loading});return e.then(e=>(U.success(E(t.success,e),{id:r,...n,...null==n?void 0:n.success}),e)).catch(e=>{U.error(E(t.error,e),{id:r,...n,...null==n?void 0:n.error})}),e};var V=(e,t)=>{O({type:1,toast:{id:e,height:t}})},q=()=>{O({type:5,time:Date.now()})},B=e=>{let{toasts:t,pausedAt:n}=L(e);(0,a.useEffect)(()=>{if(n)return;let e=Date.now(),r=t.map(t=>{if(t.duration===1/0)return;let n=(t.duration||0)+t.pauseDuration-(e-t.createdAt);if(n<0){t.visible&&U.dismiss(t.id);return}return setTimeout(()=>U.dismiss(t.id),n)});return()=>{r.forEach(e=>e&&clearTimeout(e))}},[t,n]);let r=(0,a.useCallback)(()=>{n&&O({type:6,time:Date.now()})},[n]),i=(0,a.useCallback)((e,n)=>{let{reverseOrder:r=!1,gutter:i=8,defaultPosition:s}=n||{},a=t.filter(t=>(t.position||s)===(e.position||s)&&t.height),o=a.findIndex(t=>t.id===e.id),l=a.filter((e,t)=>t<o&&e.visible).length;return a.filter(e=>e.visible).slice(...r?[l+1]:[0,l]).reduce((e,t)=>e+(t.height||0)+i,0)},[t]);return{toasts:t,handlers:{updateHeight:V,startPause:q,endPause:r,calculateOffset:i}}},j=I("div")`
  width: 20px;
  opacity: 0;
  height: 20px;
  border-radius: 10px;
  background: ${e=>e.primary||"#ff4b4b"};
  position: relative;
  transform: rotate(45deg);

  animation: ${b`
from {
  transform: scale(0) rotate(45deg);
	opacity: 0;
}
to {
 transform: scale(1) rotate(45deg);
  opacity: 1;
}`} 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275)
    forwards;
  animation-delay: 100ms;

  &:after,
  &:before {
    content: '';
    animation: ${b`
from {
  transform: scale(0);
  opacity: 0;
}
to {
  transform: scale(1);
  opacity: 1;
}`} 0.15s ease-out forwards;
    animation-delay: 150ms;
    position: absolute;
    border-radius: 3px;
    opacity: 0;
    background: ${e=>e.secondary||"#fff"};
    bottom: 9px;
    left: 4px;
    height: 2px;
    width: 12px;
  }

  &:before {
    animation: ${b`
from {
  transform: scale(0) rotate(90deg);
	opacity: 0;
}
to {
  transform: scale(1) rotate(90deg);
	opacity: 1;
}`} 0.15s ease-out forwards;
    animation-delay: 180ms;
    transform: rotate(90deg);
  }
`,$=I("div")`
  width: 12px;
  height: 12px;
  box-sizing: border-box;
  border: 2px solid;
  border-radius: 100%;
  border-color: ${e=>e.secondary||"#e0e0e0"};
  border-right-color: ${e=>e.primary||"#616161"};
  animation: ${b`
  from {
    transform: rotate(0deg);
  }
  to {
    transform: rotate(360deg);
  }
`} 1s linear infinite;
`,z=I("div")`
  width: 20px;
  opacity: 0;
  height: 20px;
  border-radius: 10px;
  background: ${e=>e.primary||"#61d345"};
  position: relative;
  transform: rotate(45deg);

  animation: ${b`
from {
  transform: scale(0) rotate(45deg);
	opacity: 0;
}
to {
  transform: scale(1) rotate(45deg);
	opacity: 1;
}`} 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275)
    forwards;
  animation-delay: 100ms;
  &:after {
    content: '';
    box-sizing: border-box;
    animation: ${b`
0% {
	height: 0;
	width: 0;
	opacity: 0;
}
40% {
  height: 0;
	width: 6px;
	opacity: 1;
}
100% {
  opacity: 1;
  height: 10px;
}`} 0.2s ease-out forwards;
    opacity: 0;
    animation-delay: 200ms;
    position: absolute;
    border-right: 2px solid;
    border-bottom: 2px solid;
    border-color: ${e=>e.secondary||"#fff"};
    bottom: 6px;
    left: 6px;
    height: 10px;
    width: 6px;
  }
`,G=I("div")`
  position: absolute;
`,K=I("div")`
  position: relative;
  display: flex;
  justify-content: center;
  align-items: center;
  min-width: 20px;
  min-height: 20px;
`,H=I("div")`
  position: relative;
  transform: scale(0.6);
  opacity: 0.4;
  min-width: 20px;
  animation: ${b`
from {
  transform: scale(0.6);
  opacity: 0.4;
}
to {
  transform: scale(1);
  opacity: 1;
}`} 0.3s 0.12s cubic-bezier(0.175, 0.885, 0.32, 1.275)
    forwards;
`,W=({toast:e})=>{let{icon:t,type:n,iconTheme:r}=e;return void 0!==t?"string"==typeof t?a.createElement(H,null,t):t:"blank"===n?null:a.createElement(K,null,a.createElement($,{...r}),"loading"!==n&&a.createElement(G,null,"error"===n?a.createElement(j,{...r}):a.createElement(z,{...r})))},Q=e=>`
0% {transform: translate3d(0,${-200*e}%,0) scale(.6); opacity:.5;}
100% {transform: translate3d(0,0,0) scale(1); opacity:1;}
`,Y=e=>`
0% {transform: translate3d(0,0,-1px) scale(1); opacity:1;}
100% {transform: translate3d(0,${-150*e}%,-1px) scale(.6); opacity:0;}
`,X=I("div")`
  display: flex;
  align-items: center;
  background: #fff;
  color: #363636;
  line-height: 1.3;
  will-change: transform;
  box-shadow: 0 3px 10px rgba(0, 0, 0, 0.1), 0 3px 3px rgba(0, 0, 0, 0.05);
  max-width: 350px;
  pointer-events: auto;
  padding: 8px 10px;
  border-radius: 8px;
`,J=I("div")`
  display: flex;
  justify-content: center;
  margin: 4px 10px;
  color: inherit;
  flex: 1 1 auto;
  white-space: pre-line;
`,Z=(e,t)=>{let n=e.includes("top")?1:-1,[r,i]=k()?["0%{opacity:0;} 100%{opacity:1;}","0%{opacity:1;} 100%{opacity:0;}"]:[Q(n),Y(n)];return{animation:t?`${b(r)} 0.35s cubic-bezier(.21,1.02,.73,1) forwards`:`${b(i)} 0.4s forwards cubic-bezier(.06,.71,.55,1)`}},ee=a.memo(({toast:e,position:t,style:n,children:r})=>{let i=e.height?Z(e.position||t||"top-center",e.visible):{opacity:0},s=a.createElement(W,{toast:e}),o=a.createElement(J,{...e.ariaProps},E(e.message,e));return a.createElement(X,{className:e.className,style:{...i,...n,...e.style}},"function"==typeof r?r({icon:s,message:o}):a.createElement(a.Fragment,null,s,o))});s=a.createElement,d.p=void 0,v=s,w=void 0,_=void 0;var et=({id:e,className:t,style:n,onHeightUpdate:r,children:i})=>{let s=a.useCallback(t=>{if(t){let n=()=>{r(e,t.getBoundingClientRect().height)};n(),new MutationObserver(n).observe(t,{subtree:!0,childList:!0,characterData:!0})}},[e,r]);return a.createElement("div",{ref:s,className:t,style:n},i)},en=(e,t)=>{let n=e.includes("top"),r=e.includes("center")?{justifyContent:"center"}:e.includes("right")?{justifyContent:"flex-end"}:{};return{left:0,right:0,display:"flex",position:"absolute",transition:k()?void 0:"all 230ms cubic-bezier(.21,1.02,.73,1)",transform:`translateY(${t*(n?1:-1)}px)`,...n?{top:0}:{bottom:0},...r}},er=y`
  z-index: 9999;
  > * {
    pointer-events: auto;
  }
`,ei=({reverseOrder:e,position:t="top-center",toastOptions:n,gutter:r,children:i,containerStyle:s,containerClassName:o})=>{let{toasts:l,handlers:u}=B(n);return a.createElement("div",{style:{position:"fixed",zIndex:9999,top:16,left:16,right:16,bottom:16,pointerEvents:"none",...s},className:o,onMouseEnter:u.startPause,onMouseLeave:u.endPause},l.map(n=>{let s=n.position||t,o=en(s,u.calculateOffset(n,{reverseOrder:e,gutter:r,defaultPosition:t}));return a.createElement(et,{id:n.id,key:n.id,onHeightUpdate:u.updateHeight,className:n.visible?er:"",style:o},"custom"===n.type?E(n.message,n):i?i(n):a.createElement(ee,{toast:n,position:s}))}))},es=U}},function(e){var t=function(t){return e(e.s=t)};e.O(0,[774,179],function(){return t(1118),t(880)}),_N_E=e.O()}]);