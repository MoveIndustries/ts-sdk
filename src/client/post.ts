// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

import { MovementConfig } from "../api/movementConfig";
import { AnyNumber, ClientConfig, MimeType, MovementResponse } from "../types";
import { MovementApiType } from "../utils/const";
import { aptosRequest } from "./core";

/**
 * Options for making a POST request, including the API client configuration.
 * @group Implementation
 * @category Client
 */
export type PostRequestOptions = {
  /**
   * The config for the API client
   * @group Implementation
   * @category Client
   */
  movementConfig: MovementConfig;
  /**
   * The type of API endpoint to call e.g. fullnode, indexer, etc
   * @group Implementation
   * @category Client
   */
  type: MovementApiType;
  /**
   * The name of the API method
   * @group Implementation
   * @category Client
   */
  originMethod: string;
  /**
   * The URL path to the API method
   * @group Implementation
   * @category Client
   */
  path: string;
  /**
   * The content type of the request body
   * @group Implementation
   * @category Client
   */
  contentType?: MimeType;
  /**
   * The accepted content type of the response of the API
   * @group Implementation
   * @category Client
   */
  acceptType?: MimeType;
  /**
   * The query parameters for the request
   * @group Implementation
   * @category Client
   */
  params?: Record<string, string | AnyNumber | boolean | undefined>;
  /**
   * The body of the request, should match the content type of the request
   * @group Implementation
   * @category Client
   */
  body?: any;
  /**
   * Specific client overrides for this request to override movementConfig
   * @group Implementation
   * @category Client
   */
  overrides?: ClientConfig;
};

/**
 * Options for posting a request to Movement, excluding the type field.
 * @group Implementation
 * @category Client
 */
export type PostAptosRequestOptions = Omit<PostRequestOptions, "type">;

/**
 * Executes a POST request to the specified URL with the provided options.
 *
 * @param options - The options for the POST request.
 * @param options.type - The type of the request.
 * @param options.originMethod - The original method that initiated the request.
 * @param options.path - The path for the request.
 * @param options.body - The body content to be sent with the request.
 * @param options.acceptType - The type of response expected from the server.
 * @param options.contentType - The content type of the request body.
 * @param options.params - Additional parameters to include in the request.
 * @param options.movementConfig - Configuration settings for the Movement request.
 * @param options.overrides - Any overrides for the default request behavior.
 * @returns The response from the POST request.
 * @group Implementation
 * @category Client
 */
export async function post<Req extends {}, Res extends {}>(
  options: PostRequestOptions,
): Promise<MovementResponse<Req, Res>> {
  const { type, originMethod, path, body, acceptType, contentType, params, movementConfig, overrides } = options;
  const url = movementConfig.getRequestUrl(type);

  return aptosRequest<Req, Res>(
    {
      url,
      method: "POST",
      originMethod,
      path,
      body,
      contentType,
      acceptType,
      params,
      overrides,
    },
    movementConfig,
    options.type,
  );
}

/**
 * Sends a request to the Movement full node using the specified options.
 * This function allows you to interact with the Movement blockchain by sending requests to the full node.
 *
 * @param options - The options for the request.
 * @param options.movementConfig - Configuration settings for the Movement client.
 * @param options.movementConfig.clientConfig - Client-specific configuration settings.
 * @param options.movementConfig.fullnodeConfig - Full node-specific configuration settings.
 * @param options.overrides - Additional overrides for the request.
 * @group Implementation
 * @category Client
 */
export async function postAptosFullNode<Req extends {}, Res extends {}>(
  options: PostAptosRequestOptions,
): Promise<MovementResponse<Req, Res>> {
  const { movementConfig } = options;

  return post<Req, Res>({
    ...options,
    type: MovementApiType.FULLNODE,
    overrides: {
      ...movementConfig.clientConfig,
      ...movementConfig.fullnodeConfig,
      ...options.overrides,
      HEADERS: { ...movementConfig.clientConfig?.HEADERS, ...movementConfig.fullnodeConfig?.HEADERS },
    },
  });
}

/**
 * Sends a request to the Movement indexer with the specified options.
 * This function allows you to interact with the Movement indexer and customize the request using various configurations.
 *
 * @param options - The options for the request to the Movement indexer.
 * @param options.movementConfig - Configuration settings specific to the Movement client and indexer.
 * @param options.movementConfig.clientConfig - The client configuration settings.
 * @param options.movementConfig.indexerConfig - The indexer configuration settings.
 * @param options.overrides - Additional overrides for the request.
 * @param options.overrides.HEADERS - Custom headers to include in the request.
 * @group Implementation
 * @category Client
 */
export async function postAptosIndexer<Req extends {}, Res extends {}>(
  options: PostAptosRequestOptions,
): Promise<MovementResponse<Req, Res>> {
  const { movementConfig } = options;

  return post<Req, Res>({
    ...options,
    type: MovementApiType.INDEXER,
    overrides: {
      ...movementConfig.clientConfig,
      ...movementConfig.indexerConfig,
      ...options.overrides,
      HEADERS: { ...movementConfig.clientConfig?.HEADERS, ...movementConfig.indexerConfig?.HEADERS },
    },
  });
}

/**
 * Sends a request to the Movement faucet to obtain test tokens.
 * This function modifies the provided configuration to ensure that the API_KEY is not included in the request.
 *
 * Note that only devnet has a publicly accessible faucet. For testnet, you must use
 * the minting page at https://movement.dev/network/faucet.
 *
 * @param options - The options for the request.
 * @param options.movementConfig - The configuration settings for the Movement client.
 * @param options.movementConfig.clientConfig - The client-specific configuration settings.
 * @param options.movementConfig.clientConfig.HEADERS - Optional headers to include in the request.
 * @param options.movementConfig.faucetConfig - The configuration settings specific to the faucet.
 * @param options.overrides - Additional overrides for the request configuration.
 * @group Implementation
 * @category Client
 */
export async function postAptosFaucet<Req extends {}, Res extends {}>(
  options: PostAptosRequestOptions,
): Promise<MovementResponse<Req, Res>> {
  const { movementConfig } = options;
  // Faucet does not support API_KEY
  // Create a new object with the desired modification
  const modifiedMovementConfig = {
    ...movementConfig,
    clientConfig: { ...movementConfig.clientConfig },
  };
  // Delete API_KEY config
  delete modifiedMovementConfig?.clientConfig?.API_KEY;

  return post<Req, Res>({
    ...options,
    type: MovementApiType.FAUCET,
    overrides: {
      ...modifiedMovementConfig.clientConfig,
      ...modifiedMovementConfig.faucetConfig,
      ...options.overrides,
      HEADERS: { ...modifiedMovementConfig.clientConfig?.HEADERS, ...modifiedMovementConfig.faucetConfig?.HEADERS },
    },
  });
}

/**
 * Makes a post request to the pepper service.
 *
 * @param options - The options for the request.
 * @param options.url - The URL to which the request is sent.
 * @param options.headers - The headers to include in the request.
 * @param options.body - The body of the request.
 * @returns A promise that resolves to the response from the pepper service.
 * @group Implementation
 * @category Client
 */
export async function postAptosPepperService<Req extends {}, Res extends {}>(
  options: PostAptosRequestOptions,
): Promise<MovementResponse<Req, Res>> {
  return post<Req, Res>({ ...options, type: MovementApiType.PEPPER });
}

/**
 * Sends a request to the Movement proving service with the specified options.
 *
 * @param options - The options for the request to the Movement proving service.
 * @param options.type - The type of the request, which should be set to MovementApiType.PROVER.
 * @param options.data - The data to be included in the request.
 * @group Implementation
 * @category Client
 */
export async function postAptosProvingService<Req extends {}, Res extends {}>(
  options: PostAptosRequestOptions,
): Promise<MovementResponse<Req, Res>> {
  return post<Req, Res>({ ...options, type: MovementApiType.PROVER });
}
