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
import {
  DEFAULT_NAMESPACE,
  stringifyEntityRef,
} from '@backstage/catalog-model';
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
  AuthProviderFactory,
  RedirectInfo,
  SignInResolver,
} from '../types';
import { OAuthProviderHandlers } from './OAuthProviderHandlers';
import {
  executeFrameHandlerStrategy,
  executeRedirectStrategy,
  PassportDoneCallback,
  makeProfileInfo,
} from '../../lib/passport';
import { TokenIssuer } from '../../identity';
import { CatalogIdentityClient } from '../../lib/catalog';
import passport from 'passport';
import { Logger } from 'winston';

type PrivateInfo = {
  refreshToken: string;
};

export type OpenAMAuthProviderOptions = OAuthProviderOptions & {
  signInResolver?: SignInResolver<OAuthResult>;
  authHandler: AuthHandler<OAuthResult>;
  tokenIssuer: TokenIssuer;
  catalogIdentityClient: CatalogIdentityClient;
  authorizationUrl: string;
  tokenUrl: string;
  scope?: string;
  logger: Logger;
  includeBasicAuth?: boolean;
}

export class OpenAMAuthProvider implements OAuthProviderHandlers {
  private readonly _strategy: OAuth2Strategy;
  private readonly signInResolver?: SignInResolver<OAuthResult>;
  private readonly authHandler: AuthHandler<OAuthResult>;
  private readonly tokenIssuer: TokenIssuer;
  private readonly catalogIdentityClient: CatalogIdentityClient;
  private readonly logger: Logger;

  constructor(options: OpenAMAuthProviderOptions) {
    this.signInResolver = options.signInResolver;
    this.authHandler = options.authHandler;
    this.tokenIssuer = options.tokenIssuer;
    this.catalogIdentityClient = options.catalogIdentityClient;
    this.logger = options.logger;

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

  async handler(req: express.Request) {
    const { result, privateInfo } = await executeFrameHandlerStrategy<
      OAuthResult,
      PrivateInfo
    >(req, this._strategy);

    return {
      response: await this.handleResult(result),
      refreshToken: privateInfo.refreshToken,
    };
  }

  encodeClientCredentials(clientID: string, clientSecret: string): string {
    return Buffer.from(`${clientID}:${clientSecret}`).toString('base64');
  }

  private async handleResult(result: OAuthResult) {
    const context: AuthResolverContext = {
      logger: this.logger,
      catalogIdentityClient: this.catalogIdentityClient,
      tokenIssuer: this.tokenIssuer,
    };
    const { profile } = await this.authHandler(result, context);

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
        context,
      );
    }

    return response;
  }
}

export const openAMDefaultSignInResolver: SignInResolver<OAuthResult> = async (
  info,
  ctx,
) => {
  const { profile } = info;

  if (!profile.email) {
    throw new Error('Profile contained no email');
  }

  const userId = profile.email.split('@')[0];

  const entityRef = stringifyEntityRef({
    kind: 'User',
    namespace: DEFAULT_NAMESPACE,
    name: userId,
  });

  const token = await ctx.tokenIssuer.issueToken({
    claims: {
      sub: entityRef,
      ent: [entityRef],
    },
  });

  return { id: userId, token };
};

export type OpenAMProviderOptions = {
  authHandler?: AuthHandler<OAuthResult>;

  signIn?: {
    resolver?: SignInResolver<OAuthResult>;
  };
};

export const createOpenAMProvider = (
  options?: OpenAMProviderOptions,
): AuthProviderFactory => {
  return ({
    providerId,
    globalConfig,
    config,
    tokenIssuer,
    tokenManager,
    catalogApi,
    logger,
  }) =>
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
      const includeBasicAuth = envConfig.getOptionalBoolean('includeBasicAuth');
      const disableRefresh =
        envConfig.getOptionalBoolean('disableRefresh') ?? false;

      const catalogIdentityClient = new CatalogIdentityClient({
        catalogApi,
        tokenManager,
      });

      const authHandler: AuthHandler<OAuthResult> = options?.authHandler
        ? options.authHandler
        : async ({ fullProfile, params }) => ({
            profile: makeProfileInfo(fullProfile, params.id_token),
          });

      const signInResolverFn =
        options?.signIn?.resolver ?? openAMDefaultSignInResolver;

      const signInResolver: SignInResolver<OAuthResult> = info =>
        signInResolverFn(info, {
          catalogIdentityClient,
          tokenIssuer,
          logger,
        });

      const provider = new OpenAMAuthProvider({
        clientId,
        clientSecret,
        tokenIssuer,
        catalogIdentityClient,
        callbackUrl,
        signInResolver,
        authHandler,
        authorizationUrl,
        tokenUrl,
        scope,
        logger,
        includeBasicAuth,
      });

      return OAuthAdapter.fromConfig(globalConfig, provider, {
        disableRefresh,
        providerId,
        tokenIssuer,
        callbackUrl,
      });
    });
};
