/*
 * Copyright 2022 The Backstage Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import { Strategy as OAuth2Strategy } from 'passport-oauth2';
import express from 'express';
import {
  OAuthProviderOptions,
  OAuthResult,
  OAuthStartRequest,
  encodeState,
  OAuthResponse,
  OAuthEnvironmentHandler,
  OAuthAdapter,
} from '../../lib/oauth';
import {
  AuthHandler,
  AuthResolverContext,
  RedirectInfo,
  SignInResolver,
} from '../types';
import { OAuthProviderHandlers } from './OAuthProviderHandlers';
import {
  executeFrameHandlerStrategy,
  executeRedirectStrategy,
  makeProfileInfo,
  PassportDoneCallback,
} from '../../lib/passport';
import passport from 'passport';
import { createAuthProviderIntegration } from '../createAuthProviderIntegration';

type PrivateInfo = {
  refreshToken: string;
};

export type OpenAMAuthProviderOptions = OAuthProviderOptions & {
  signInResolver?: SignInResolver<OAuthResult>;
  authHandler: AuthHandler<OAuthResult>;
  authorizationUrl: string;
  tokenUrl: string;
  scope?: string;
  resolverContext: AuthResolverContext;
  includeBasicAuth?: boolean;
};

export class OpenAMAuthProvider implements OAuthProviderHandlers {
  private readonly _strategy: OAuth2Strategy;
  private readonly signInResolver?: SignInResolver<OAuthResult>;
  private readonly authHandler: AuthHandler<OAuthResult>;
  private readonly resolverContext: AuthResolverContext;

  constructor(options: OpenAMAuthProviderOptions) {
    this.authHandler = options.authHandler;
    this.resolverContext = options.resolverContext;
    this.signInResolver = options.signInResolver;

    this._strategy = new OAuth2Strategy(
      {
        clientID: options.clientId,
        clientSecret: options.clientSecret,
        callbackURL: options.callbackUrl,
        authorizationURL: options.authorizationUrl,
        tokenURL: options.tokenUrl,
        passReqToCallback: false as true,
        scope: options.scope,
        customHeaders: options.includeBasicAuth
          ? {
              Authorization: `Basic ${this.encodeClientCredentials(
                options.clientId,
                options.clientSecret,
              )}`,
            }
          : undefined,
      },
      (
        accessToken: any,
        refreshToken: any,
        params: any,
        fullProfile: passport.Profile,
        done: PassportDoneCallback<OAuthResult, PrivateInfo>,
      ) => {
        done(
          undefined,
          {
            fullProfile,
            accessToken,
            refreshToken,
            params,
          },
          {
            refreshToken,
          },
        );
      },
    );
  }

  async start(req: OAuthStartRequest): Promise<RedirectInfo> {
    return await executeRedirectStrategy(req, this._strategy, {
      accessType: 'offline',
      prompt: 'consent',
      scope: req.scope,
      state: encodeState(req.state),
    });
  }

  async handler(req: express.Request): Promise<{
    response: OAuthResponse;
    refreshToken?: string;
  }> {
    const { result, privateInfo } = await executeFrameHandlerStrategy<
      OAuthResult,
      PrivateInfo
    >(req, this._strategy);

    return {
      response: await this.handleResult(result),
      refreshToken: privateInfo.refreshToken,
    };
  }

  private async handleResult(result: OAuthResult) {
    const { profile } = await this.authHandler(result, this.resolverContext);

    const response: OAuthResponse = {
      providerInfo: {
        idToken: result.params.id_token,
        accessToken: result.accessToken,
        scope: result.params.scope,
        expiresInSeconds: result.params.expires_in,
      },
      profile,
    };

    if (this.signInResolver) {
      response.backstageIdentity = await this.signInResolver(
        {
          result,
          profile,
        },
        this.resolverContext,
      );
    }

    return response;
  }

  encodeClientCredentials(clientID: string, clientSecret: string): string {
    return Buffer.from(`${clientID}:${clientSecret}`).toString('base64');
  }
}

/**
 * @public
 * @deprecated This type has been inlined into the create method and will be removed.
 */
export type OpenAMProviderOptions = {
  authHandler?: AuthHandler<OAuthResult>;

  signIn?: {
    resolver: SignInResolver<OAuthResult>;
  };
};

/**
 * Auth provider integration for OpenAM auth
 *
 * @public
 */
export const openam = createAuthProviderIntegration({
  create(options?: {
    authHandler?: AuthHandler<OAuthResult>;

    signIn?: {
      resolver: SignInResolver<OAuthResult>;
    };
  }) {
    return ({ providerId, globalConfig, config, resolverContext }) =>
      OAuthEnvironmentHandler.mapConfig(config, envConfig => {
        const clientId = envConfig.getString('clientId');
        const clientSecret = envConfig.getString('clientSecret');
        const customCallbackUrl = envConfig.getOptionalString('callbackUrl');
        const callbackUrl =
          customCallbackUrl ||
          `${globalConfig.baseUrl}/${providerId}/handler/frame`;
        const authorizationUrl = envConfig.getString('authorizationUrl');
        const tokenUrl = envConfig.getString('tokenUrl');
        const scope = envConfig.getOptionalString('scope');
        const includeBasicAuth =
          envConfig.getOptionalBoolean('includeBasicAuth');
        const disableRefresh =
          envConfig.getOptionalBoolean('disableRefresh') ?? false;

        const authHandler: AuthHandler<OAuthResult> = options?.authHandler
          ? options.authHandler
          : async ({ fullProfile, params }) => ({
              profile: makeProfileInfo(fullProfile, params.id_token),
            });

        const provider = new OpenAMAuthProvider({
          clientId,
          clientSecret,
          callbackUrl,
          signInResolver: options?.signIn?.resolver,
          authHandler,
          authorizationUrl,
          tokenUrl,
          scope,
          includeBasicAuth,
          resolverContext,
        });

        return OAuthAdapter.fromConfig(globalConfig, provider, {
          disableRefresh,
          providerId,
          callbackUrl,
        });
      });
  },
});

/**
 * @public
 * @deprecated Use `providers.openam.create` instead
 */
export const createOpenAMProvider = openam.create;
