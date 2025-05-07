import 'dart:async';
import 'dart:convert';
import 'dart:js_interop';

import 'package:aad_oauth/helper/core_oauth.dart';
import 'package:aad_oauth/model/config.dart';
import 'package:aad_oauth/model/failure.dart';
import 'package:aad_oauth/model/token.dart';
import 'package:dartz/dartz.dart';

/// Bind to the existing global `window.aadOauth` object (not a constructor)
@JS('aadOauth')
@staticInterop
class AadOauthJS {}

@JS('aadOauth')
external AadOauthJS get aadOauth;

extension _AadOauthJSExt on AadOauthJS {
  external void init(MsalConfigInterop config);
  external JSPromise getAccessToken();
  external JSPromise getIdToken();
  external bool hasCachedAccountInformation();
  external void login(
    bool refreshIfAvailable,
    bool useRedirect,
    JSFunction onSuccess,
    JSFunction onError,
  );
  external void refreshToken(
    JSFunction onSuccess,
    JSFunction onError,
  );
  external void logout(
    JSFunction onSuccess,
    JSFunction onError,
    bool showPopup,
  );
}

@JS()
@staticInterop
@anonymous
class MsalConfigInterop {
  external factory MsalConfigInterop({
    required String tenant,
    String? policy,
    required String clientId,
    required String responseType,
    required String redirectUri,
    required String scope,
    String? responseMode,
    String? state,
    String? prompt,
    String? codeChallenge,
    String? codeChallengeMethod,
    String? nonce,
    String? tokenIdentifier,
    String? clientSecret,
    String? resource,
    required bool isB2C,
    String? customAuthorizationUrl,
    String? customTokenUrl,
    String? loginHint,
    String? domainHint,
    String? codeVerifier,
    String? authorizationUrl,
    String? tokenUrl,
    required String cacheLocation,
    required String customParameters,
    String? postLogoutRedirectUri,
  });
}

extension MsalConfigInteropProps on MsalConfigInterop {
  external String get tenant;
  external String? get policy;
  external String get clientId;
  external String get responseType;
  external String get redirectUri;
  external String get scope;
  external String? get responseMode;
  external String? get state;
  external String? get prompt;
  external String? get codeChallenge;
  external String? get codeChallengeMethod;
  external String? get nonce;
  external String? get tokenIdentifier;
  external String? get clientSecret;
  external String? get resource;
  external bool get isB2C;
  external String? get customAuthorizationUrl;
  external String? get customTokenUrl;
  external String? get loginHint;
  external String? get domainHint;
  external String? get codeVerifier;
  external String? get authorizationUrl;
  external String? get tokenUrl;
  external String get cacheLocation;
  external String get customParameters;
  external String? get postLogoutRedirectUri;
}

class WebOAuth extends CoreOAuth {
  final Config config;
  final _js = aadOauth;

  WebOAuth(this.config) {
    _js.init(MsalConfigInterop(
      tenant: config.tenant,
      policy: config.policy,
      clientId: config.clientId,
      responseType: config.responseType,
      redirectUri: config.redirectUri,
      scope: config.scope,
      responseMode: config.responseMode,
      state: config.state,
      prompt: config.prompt,
      codeChallenge: config.codeChallenge,
      codeChallengeMethod: config.codeChallengeMethod,
      nonce: config.nonce,
      tokenIdentifier: config.tokenIdentifier,
      clientSecret: config.clientSecret,
      resource: config.resource,
      isB2C: config.isB2C,
      customAuthorizationUrl: config.customAuthorizationUrl,
      customTokenUrl: config.customTokenUrl,
      loginHint: config.loginHint,
      domainHint: config.domainHint,
      codeVerifier: config.codeVerifier,
      authorizationUrl: config.authorizationUrl,
      tokenUrl: config.tokenUrl,
      cacheLocation: config.cacheLocation.value,
      customParameters: jsonEncode(config.customParameters),
      postLogoutRedirectUri: config.postLogoutRedirectUri,
    ));
  }

  @override
  Future<String?> getAccessToken() async {
    final jsVal = await _js.getAccessToken().toDart;
    return (jsVal as JSString?)?.toDart;
  }

  @override
  Future<String?> getIdToken() async {
    final jsVal = await _js.getIdToken().toDart;
    return (jsVal as JSString?)?.toDart;
  }

  @override
  Future<bool> get hasCachedAccountInformation async =>
      _js.hasCachedAccountInformation();

  @override
  Future<Either<Failure, Token>> login({bool refreshIfAvailable = false}) {
    final c = Completer<Either<Failure, Token>>();
    _js.login(
      refreshIfAvailable,
      config.webUseRedirect,
      ((JSString accessToken) {
        c.complete(Right(Token(accessToken: accessToken.toDart)));
      }).toJS,
      ((JSAny error) {
        c.complete(Left(AadOauthFailure(
          errorType: ErrorType.accessDeniedOrAuthenticationCanceled,
          message: 'Access denied or authentication canceled. Error: $error',
        )));
      }).toJS,
    );
    return c.future;
  }

  @override
  Future<Either<Failure, Token>> refreshToken() {
    final c = Completer<Either<Failure, Token>>();
    _js.refreshToken(
      ((JSString accessToken) {
        c.complete(Right(Token(accessToken: accessToken.toDart)));
      }).toJS,
      ((JSAny error) {
        c.complete(Left(AadOauthFailure(
          errorType: ErrorType.accessDeniedOrAuthenticationCanceled,
          message: 'Access denied or authentication canceled. Error: $error',
        )));
      }).toJS,
    );
    return c.future;
  }

  @override
  Future<void> logout({bool showPopup = true, bool clearCookies = true}) {
    final c = Completer<void>();
    _js.logout(
      (() => c.complete()).toJS,
      ((JSAny error) => c.completeError(error)).toJS,
      showPopup,
    );
    return c.future;
  }
}

CoreOAuth getOAuthConfig(Config config) => WebOAuth(config);
