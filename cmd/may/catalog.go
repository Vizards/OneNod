package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

func runCatalog(args []string, config cliConfig, deps dependencies) error {
	if len(args) < 2 || args[0] != "search" {
		return errors.New(catalogSearchUsage)
	}
	query := strings.TrimSpace(strings.Join(args[1:], " "))
	if query == "" {
		return errors.New("catalog query is required")
	}
	credential, err := deps.keychain.Load()
	if err != nil {
		return err
	}
	client, err := newAPIClient(config.origin, credential, deps.httpClient)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(
		context.Background(),
		gatewayRequestTimeout,
	)
	defer cancel()
	response, err := searchCatalogWithLocalFallback(ctx, client, query, deps)
	if err != nil {
		return err
	}
	return writeIndentedValue(deps.stdout, response)
}

func searchCatalog(
	ctx context.Context,
	client *apiClient,
	query string,
) (catalogSearchResponse, error) {
	var response catalogSearchResponse
	if err := client.doJSON(
		ctx,
		http.MethodPost,
		"/v1/catalog/search",
		catalogSearchRequest{Query: query},
		&response,
	); err != nil {
		return catalogSearchResponse{}, err
	}
	if response.Items == nil {
		return catalogSearchResponse{}, errors.New("gateway catalog response did not include items")
	}
	return response, nil
}

func resolveExpectedVersion(
	ctx context.Context,
	client *apiClient,
	itemID string,
) (int64, error) {
	response, err := searchCatalog(ctx, client, itemID)
	if err != nil {
		return 0, fmt.Errorf("resolve expected version: %w", err)
	}
	return expectedVersionFromCatalog(response, itemID)
}

func resolveExpectedVersionWithLocalFallback(
	ctx context.Context,
	client *apiClient,
	itemID string,
	deps dependencies,
) (int64, error) {
	response, err := searchCatalogWithLocalFallback(ctx, client, itemID, deps)
	if err != nil {
		return 0, fmt.Errorf("resolve expected version: %w", err)
	}
	return expectedVersionFromCatalog(response, itemID)
}

func expectedVersionFromCatalog(
	response catalogSearchResponse,
	itemID string,
) (int64, error) {
	var version int64
	matches := 0
	for _, item := range response.Items {
		if item.ItemID != itemID {
			continue
		}
		if item.Version <= 0 {
			return 0, errors.New("catalog returned a non-positive item version")
		}
		version = item.Version
		matches++
	}
	if matches == 0 {
		return 0, errors.New(
			"catalog did not return the requested item; pass --expected-version explicitly",
		)
	}
	if matches > 1 {
		return 0, errors.New("catalog returned duplicate entries for the requested item")
	}
	return version, nil
}
