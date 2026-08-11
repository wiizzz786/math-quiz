# Requirements Document

## Introduction

This feature adds two complementary capabilities to the Void proxy server:

1. **Search Result Caching** — When a user submits a search query through the `/go` route, the server resolves it to a full search-engine URL and proxies the result. Currently, repeated identical queries always re-fetch the remote page. This requirement introduces a dedicated cache layer for search queries so that repeat queries return cached results immediately, reusing the same in-memory LRU infrastructure (`_resourceCache`) that already caches proxied resources.

2. **Serper API Integration** — Adds Serper (https://serper.dev) as a new search option alongside the existing engines (Brave, Google, DuckDuckGo, Bing, Yahoo). Because Serper is API-based rather than page-based, it requires a new server-side `/api/search` endpoint that calls the Serper API (keeping the API key secret in `SERPER_API_KEY`) and returns structured JSON results. A UI component on the front-end renders those results inline — title, snippet, and source URL for each hit — without loading a proxied page.

---

## Glossary

- **Server**: The Void Express server (`server.js`).
- **Cache**: The existing in-memory LRU `_resourceCache` Map (max 10,000 entries), accessed via `cacheGet(key)` / `cacheSet(key, ct, body)`.
- **Search_Cache**: The logical subset of Cache entries whose keys are prefixed with `"sq:"` and encode a normalised query + engine pair.
- **Query**: A non-URL text string submitted by the user as a search term.
- **Normalised_Query**: A Query that has been trimmed of leading/trailing whitespace and lowercased.
- **Cache_Key**: A string of the form `"sq:<engine>:<normalised_query>"` that uniquely identifies a cached search result.
- **Search_Engine**: One of the supported proxy-based engines: `brave`, `google`, `ddg`, `bing`, `yahoo`.
- **Serper_Engine**: The API-based search option identified by the engine key `"serper"`.
- **Serper_API**: The external REST API at `https://google.serper.dev/search` used to retrieve structured results for the Serper_Engine.
- **Serper_Result**: A single structured result item returned by the Serper_API containing at minimum a `title`, `snippet`, and `link` field.
- **Go_Route**: The existing `GET /go` Express route that resolves a URL or Query and redirects to the appropriate proxy path.
- **API_Search_Endpoint**: The new `GET /api/search` Express route introduced by this feature.
- **Search_Results_UI**: The front-end component in `public/index.html` that displays Serper_Results inline.
- **TTL**: Time-to-live; the maximum age (in milliseconds) a Search_Cache entry is considered fresh.

---

## Requirements

### Requirement 1: Search Query Cache — Cache Write

**User Story:** As a Void user, I want the server to remember the proxied result of a search query, so that I get faster responses when I repeat the same search.

#### Acceptance Criteria

1. WHEN the Go_Route resolves a Query to a Search_Engine URL and successfully proxies the resulting page, THE Server SHALL store the raw (pre-rewrite) HTML response in the Search_Cache under the corresponding Cache_Key.
2. WHEN storing a Search_Cache entry, THE Server SHALL record the entry's timestamp so that freshness can be checked on retrieval.
3. IF a Search_Cache entry for the same Cache_Key already exists, THEN THE Server SHALL replace it with the new entry.
4. WHEN the Cache has reached its maximum size of 10,000 entries and a new Search_Cache entry must be stored, THE Server SHALL evict the oldest entry in the Cache before inserting the new one.
5. THE Server SHALL construct the Cache_Key by concatenating the prefix `"sq:"`, the engine identifier, `":"`, and the Normalised_Query.

### Requirement 2: Search Query Cache — Cache Read

**User Story:** As a Void user, I want repeated identical searches to load immediately from cache, so that I don't wait for a remote fetch I've already performed.

#### Acceptance Criteria

1. WHEN the Go_Route receives a Query request and a Search_Cache entry exists for the corresponding Cache_Key, THE Server SHALL serve the cached HTML response instead of issuing a new upstream fetch.
2. WHEN serving a cached search response, THE Server SHALL set the response header `X-Void-Cache` to `"HIT"`.
3. WHEN serving a cached search response, THE Server SHALL apply the same HTML rewrite logic (`rewriteHtmlWithOpts`) used for live proxied pages before sending the response to the client.
4. WHEN a Search_Cache entry's age exceeds the TTL of 300,000 milliseconds (5 minutes), THE Server SHALL treat the entry as stale and perform a fresh upstream fetch instead of serving the cached value.
5. IF a fresh upstream fetch succeeds after a stale cache hit, THEN THE Server SHALL update the Search_Cache entry with the new response and timestamp.
6. THE Server SHALL normalise a Query by trimming whitespace and converting to lowercase before computing the Cache_Key, so that `"OpenAI"` and `" openai "` resolve to the same cache entry.

### Requirement 3: Search Query Cache — Cache Invalidation and Eviction

**User Story:** As a Void operator, I want stale search results to be evicted automatically, so that the cache does not serve outdated pages indefinitely.

#### Acceptance Criteria

1. THE Server SHALL reuse the existing LRU eviction policy: WHEN the Cache is at capacity, THE Server SHALL delete the oldest entry (by insertion order) before writing a new one.
2. WHEN a Search_Cache entry is read and found to be stale (age > TTL), THE Server SHALL delete that entry from the Cache before initiating the fresh fetch.
3. THE Server SHALL NOT introduce a separate cache data structure; all Search_Cache entries SHALL reside in the existing `_resourceCache` Map alongside proxied-resource entries.

### Requirement 4: Serper Engine — Server-Side API Endpoint

**User Story:** As a Void user, I want to search via Serper and see structured results in the page, so that I can browse search results without loading a full proxied search-engine page.

#### Acceptance Criteria

1. THE Server SHALL expose a `GET /api/search` endpoint that accepts query parameters `q` (search query string) and `engine` (search engine identifier).
2. WHEN the API_Search_Endpoint receives a request with `engine` equal to `"serper"` and a non-empty `q` parameter, THE Server SHALL call the Serper_API with the value of `q` and return a JSON response containing an array of Serper_Result objects.
3. WHEN calling the Serper_API, THE Server SHALL include the `SERPER_API_KEY` environment variable as the `X-API-Key` request header and SHALL NOT expose this key to the client.
4. WHEN the Serper_API returns a successful response, THE Server SHALL map each organic result to an object containing exactly the fields `title` (string), `snippet` (string), and `url` (string, from the result's `link` field) and return the array under a top-level `results` key.
5. IF the `SERPER_API_KEY` environment variable is not set, THEN THE Server SHALL respond to API_Search_Endpoint requests with HTTP 503 and a JSON body `{ "error": "Serper API key not configured" }`.
6. IF the `q` parameter is absent or empty, THEN THE Server SHALL respond with HTTP 400 and a JSON body `{ "error": "Missing query parameter: q" }`.
7. IF the Serper_API returns an HTTP error status, THEN THE Server SHALL respond with HTTP 502 and a JSON body `{ "error": "Serper API error", "status": <upstream_status_code> }`.
8. IF the Serper_API request times out after 10,000 milliseconds, THEN THE Server SHALL respond with HTTP 504 and a JSON body `{ "error": "Serper API request timed out" }`.
9. THE Server SHALL cache Serper_API responses in the Search_Cache using a Cache_Key of the form `"sq:serper:<normalised_query>"`, applying the same TTL and eviction rules defined in Requirements 1–3.

### Requirement 5: Serper Engine — Front-End UI

**User Story:** As a Void user, I want to select Serper as my search engine and see structured results displayed in the page, so that I can find and navigate to content without leaving the Void interface.

#### Acceptance Criteria

1. THE Search_Results_UI SHALL add `"Serper"` as a selectable search engine option in the settings panel alongside the existing proxy-based engines.
2. WHEN a user submits a search query with the Serper engine selected, THE Search_Results_UI SHALL call the API_Search_Endpoint with the query and render the returned Serper_Results inline on the page without navigating away.
3. WHEN rendering Serper_Results, THE Search_Results_UI SHALL display for each result: the `title` as a clickable link whose `href` points to the `/go` route with the result's `url` and the current proxy mode, the `snippet` as descriptive text, and the `url` as a visible secondary line.
4. WHEN the API_Search_Endpoint returns zero results, THE Search_Results_UI SHALL display a message indicating no results were found for the query.
5. IF the API_Search_Endpoint returns an error response, THEN THE Search_Results_UI SHALL display a human-readable error message and SHALL NOT display a blank or broken layout.
6. WHILE a Serper search request is in flight, THE Search_Results_UI SHALL display a loading indicator and SHALL disable the search submit button to prevent duplicate submissions.
7. WHEN a user submits a new search query while Serper results are already displayed, THE Search_Results_UI SHALL replace the existing results with the new results.
8. THE Search_Results_UI SHALL be keyboard-navigable: result links SHALL be reachable via the Tab key and activatable via Enter.

### Requirement 6: Serper Engine — Go Route Exclusion

**User Story:** As a Void operator, I want the `/go` route to reject Serper as a proxy-based engine, so that the existing proxy path is not invoked for an API-only engine.

#### Acceptance Criteria

1. WHEN the Go_Route receives a request with `engine` equal to `"serper"`, THE Server SHALL respond with HTTP 400 and the message `"Serper is an API-only engine. Use /api/search?engine=serper&q=<query> instead."`.
2. THE Server SHALL NOT attempt to resolve or proxy any URL when the engine parameter is `"serper"` on the Go_Route.

### Requirement 7: Configuration and Security

**User Story:** As a Void operator, I want the Serper API key to remain server-side only, so that it is never exposed in client-accessible responses or source code.

#### Acceptance Criteria

1. THE Server SHALL read the Serper API key exclusively from the `SERPER_API_KEY` environment variable and SHALL NOT hardcode any API key value in source files.
2. THE Server SHALL NOT include the `SERPER_API_KEY` value in any HTTP response body, response header, or client-side JavaScript.
3. THE Server SHALL set a `Content-Type: application/json` header on all API_Search_Endpoint responses.
4. THE Server SHALL set a `Cache-Control: no-store` header on all API_Search_Endpoint error responses so that error states are not cached by intermediate proxies.
