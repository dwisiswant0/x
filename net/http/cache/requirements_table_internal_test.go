package cache

// requirementsTable lists every BCP 14 requirement of RFC 9111 §1 to §5, and
// of the parts of RFC 9110 that the cache relies on, one per entry:
//
//	<id> | <level> | <section> | <status> | "<short quote>"
//
// The id is <rfc>-<section>-<slug>, and tests name it in covers. The level is
// the RFC keyword, or ALGORITHM for a calculation without one (RFC 9111
// §4.2.1 and §4.2.3). The status is "test", meaning a test must cover the
// requirement, "n/a: <reason>", or "deviation: <reason>" for a requirement
// that binds the cache but that it doesn't meet. The quote is a verbatim excerpt of at most
// 120 characters with whitespace normalized; "..." marks elided text.
//
// A line that starts with a tab continues the entry above it, joined with a
// space. Lines starting with # and blank lines are ignored. Sentences without
// a BCP 14 keyword aren't listed.
const requirementsTable = `
# RFC 9111 §1 Introduction
9111-1-tunnel | MAY | 9111 §1 | test | "Any client or server MAY use a cache, though not when acting as a tunnel"

# RFC 9111 §1.2.2 Delta Seconds
9111-1.2.2-overflow | MUST | 9111 §1.2.2 | test | "the cache MUST consider the value to be 2147483648 (2^31)"

# RFC 9111 §2 Overview of Cache Operation
9111-2-optional | OPTIONAL | 9111 §2 | n/a: descriptive; caching is opt-in by wrapping a transport | "Although caching
	is an entirely OPTIONAL feature of HTTP"

# RFC 9111 §3 Storing Responses in Caches
9111-3-method | MUST NOT | 9111 §3 | test | "A cache MUST NOT store a response to a request unless: ... the request
	method is understood by the cache;"
9111-3-final-status | MUST NOT | 9111 §3 | test | "A cache MUST NOT store a response to a request unless: ... the
	response status code is final"
9111-3-understood-status | MUST NOT | 9111 §3 | test | "MUST NOT store ... unless: ... is present: the cache
	understands the response status code"
9111-3-no-store | MUST NOT | 9111 §3 | test | "A cache MUST NOT store ... unless: ... the no-store cache directive is
	not present in the response"
9111-3-shared-private | MUST NOT | 9111 §3 | test | "MUST NOT store ... unless: ... if the cache is shared: the
	private response directive is either not present"
9111-3-shared-auth | MUST NOT | 9111 §3 | test | "MUST NOT store ... unless: ... if the cache is shared: the
	Authorization header field is not present in the request"
9111-3-public | MUST NOT | 9111 §3 | test | "MUST NOT store ... unless: ... at least one of the following: ... a
	public response directive"
9111-3-private-explicit | MUST NOT | 9111 §3 | test | "MUST NOT store ... unless: ... a private response directive, if
	the cache is not shared"
9111-3-expires | MUST NOT | 9111 §3 | test | "MUST NOT store ... unless: ... at least one of the following: ... an
	Expires header field"
9111-3-max-age | MUST NOT | 9111 §3 | test | "MUST NOT store ... unless: ... at least one of the following: ... a
	max-age response directive"
9111-3-s-maxage | MUST NOT | 9111 §3 | test | "MUST NOT store ... unless: ... at least one of the following: ... if
	the cache is shared: an s-maxage response directive"
9111-3-extension | MUST NOT | 9111 §3 | n/a: extension directives are not supported; unrecognized directives are
	ignored (§5.2.3) | "MUST NOT store ... unless: ... at least one of the following: ... a cache extension that allows
	it to be cached"
9111-3-heuristic-status | MUST NOT | 9111 §3 | test | "MUST NOT store ... unless: ... a status code that is defined as
	heuristically cacheable"

# RFC 9111 §3.1 Storing Header and Trailer Fields
9111-3.1-all-fields | MUST | 9111 §3.1 | test | "Caches MUST include all received response header fields -- including
	unrecognized ones -- when storing a response"
9111-3.1-connection | MAY | 9111 §3.1 | test | "This MAY be implemented by doing so before storage."
9111-3.1-hop-by-hop | MAY | 9111 §3.1 | test | "semantics require them to be removed before forwarding ... this MAY be
	implemented by doing so before storage"
9111-3.1-proxy-fields | MUST NOT | 9111 §3.1 | test | "Header fields that are specific to the proxy that a cache uses
	when forwarding a request MUST NOT be stored"
9111-3.1-trailers-store | MAY | 9111 §3.1 | test | "Caches MAY either store trailer fields separate from header fields
	or discard them."
9111-3.1-trailers-merge | MUST NOT | 9111 §3.1 | test | "Caches MUST NOT combine trailer fields with header fields."

# RFC 9111 §3.2 Updating Stored Header Fields
9111-3.2-update | MUST | 9111 §3.2 | test | "the cache MUST add each header field in the provided response to the
	stored response"
9111-3.2-omit | MAY | 9111 §3.2 | test | "Caches in this situation MAY omit these header fields from updating stored
	responses on an exceptional basis"
9111-3.2-omit-limit | SHOULD | 9111 §3.2 | test | "SHOULD limit such omission to those fields necessary to assure
	integrity of the stored response"
9111-3.2-content-range | MAY | 9111 §3.2 | test | "Implementations MAY automatically omit such header fields from
	updates"

# RFC 9111 §3.3 Storing Incomplete Responses
9111-3.3-store-incomplete | MAY | 9111 §3.3 | n/a: MAY not taken: incomplete responses are never stored | "a cache MAY
	store a response that is not complete"
9111-3.3-store-206 | MAY | 9111 §3.3 | n/a: MAY not taken: 206 responses are never stored | "a 206 (Partial Content)
	response MAY be stored as if it were an incomplete 200 (OK) response"
9111-3.3-no-partial-store | MUST NOT | 9111 §3.3 | test | "a cache MUST NOT store incomplete or partial-content
	responses if it does not support the Range"
9111-3.3-complete | MAY | 9111 §3.3 | n/a: MAY not taken: incomplete responses are never stored, so none is completed
	| "A cache MAY complete a stored incomplete response by making a subsequent range request"
9111-3.3-no-incomplete-use | MUST NOT | 9111 §3.3 | test | "A cache MUST NOT use an incomplete response to answer
	requests unless the response has been made complete"
9111-3.3-206-marking | MUST NOT | 9111 §3.3 | test | "A cache MUST NOT send a partial response to a client without
	explicitly marking it using the 206"

# RFC 9111 §3.4 Combining Partial Content
9111-3.4-combine | MAY | 9111 §3.4 | n/a: ranges are bypassed (§3.3), so combining is never done | "A cache MAY
	combine these ranges into a single stored response"
9111-3.4-update | MUST | 9111 §3.4 | n/a: ranges are bypassed (§3.3), so combining is never done | "a cache MUST
	update the stored response header fields using the header fields provided in the new response"

# RFC 9111 §3.5 Storing Responses to Authenticated Requests
9111-3.5-authorization | MUST NOT | 9111 §3.5 | test | "A shared cache MUST NOT use a cached response to a request
	with an Authorization header field"

# RFC 9111 §4 Constructing Responses from Caches
9111-4-uri | MUST NOT | 9111 §4 | test | "a cache MUST NOT reuse a stored response unless: ... the presented target
	URI ... and that of the stored response match"
9111-4-method | MUST NOT | 9111 §4 | test | "MUST NOT reuse ... unless: ... the request method associated with the
	stored response allows it to be used"
9111-4-vary | MUST NOT | 9111 §4 | test | "MUST NOT reuse ... unless: ... request header fields nominated by the
	stored response (if any) match those presented"
9111-4-no-cache | MUST NOT | 9111 §4 | test | "MUST NOT reuse ... unless: ... the stored response does not contain the
	no-cache directive"
9111-4-freshness | MUST NOT | 9111 §4 | test | "MUST NOT reuse ... unless: ... the stored response is one of the
	following: ... fresh (see Section 4.2), or"
9111-4-age | MUST | 9111 §4 | test | "a cache MUST generate an Age header field (Section 5.1), replacing any present
	in the response"
9111-4-write-through | MUST | 9111 §4 | test | "A cache MUST write through requests with methods that are unsafe"
9111-4-most-recent | MUST | 9111 §4 | test | "a cache MUST use the most recent one (as determined by the Date header
	field)"
9111-4-no-clock | MUST | 9111 §4 | n/a: the cache always has a clock | "A cache without a clock (Section 5.6.7 of
	[HTTP]) MUST revalidate stored responses upon every use"

# RFC 9111 §4.1 Calculating Cache Keys with the Vary Header Field
9111-4.1-vary-match | MUST NOT | 9111 §4.1 | test | "the cache MUST NOT use that stored response without revalidation
	unless all the presented request header fields"
9111-4.1-ranking | MAY | 9111 §4.1 | n/a: MAY not taken: ties are broken by the most recent Date only, with no qvalue
	ranking | "that mechanism MAY be used to choose a preferred response"
9111-4.1-vary-omitted | SHOULD | 9111 §4.1 | test | "the cache SHOULD choose the most recent (see Section 4.2.3)
	stored response with a valid Vary field value"

# RFC 9111 §4.2 Freshness
9111-4.2-case-insensitive | SHOULD | 9111 §4.2 | test | "a cache recipient SHOULD match the field value
	case-insensitively"
9111-4.2-expires-round | MUST | 9111 §4.2 | n/a: Go time has ns resolution | "the recipient MUST internally represent
	a parsed Expires date as the nearest time equal to or earlier"
9111-4.2-local-tz | MUST NOT | 9111 §4.2 | test | "A cache recipient MUST NOT allow local time zones to influence the
	calculation or comparison of an age"
9111-4.2-non-gmt | SHOULD | 9111 §4.2 | test | "A cache recipient SHOULD consider a date with a zone abbreviation
	other than ... to be invalid"

# RFC 9111 §4.2.1 Calculating Freshness Lifetime
9111-4.2.1-lifetime | ALGORITHM | 9111 §4.2.1 | test | "A cache can calculate the freshness lifetime ... by evaluating
	the following rules and using the first match"

# RFC 9111 §4.2.2 Calculating Heuristic Freshness
9111-4.2.2-heuristic | MAY | 9111 §4.2.2 | test | "a cache MAY assign a heuristic expiration time when an explicit
	time is not specified"
9111-4.2.2-no-explicit | MUST NOT | 9111 §4.2.2 | test | "A cache MUST NOT use heuristics to determine freshness when
	an explicit expiration time is present"

# RFC 9111 §4.2.3 Calculating Age
9111-4.2.3-age | ALGORITHM | 9111 §4.2.3 | test | "current_age = corrected_initial_age + resident_time;"
9111-4.2.3-request-time | MUST | 9111 §4.2.3 | test | "A cache MUST interpret this value relative to the time the
	request was initiated"
9111-4.2.3-corrected-age | MAY | 9111 §4.2.3 | n/a: MAY not taken: the conservative max(apparent_age,
	corrected_age_value) is always used | "The corrected_age_value MAY be used as the corrected_initial_age."

# RFC 9111 §4.2.4 Serving Stale Responses
9111-4.2.4-prohibited | MUST NOT | 9111 §4.2.4 | test | "A cache MUST NOT generate a stale response if it is
	prohibited by an explicit in-protocol directive"
9111-4.2.4-permitted | MUST NOT | 9111 §4.2.4 | test | "A cache MUST NOT generate a stale response unless it is
	disconnected or doing so is explicitly permitted"

# RFC 9111 §4.3.1 Sending a Validation Request
9111-4.3.1-etag | MUST | 9111 §4.3.1 | test | "MUST send the relevant entity tags (using If-Match, If-None-Match, or
	If-Range) if the entity tags were provided"
9111-4.3.1-ims | SHOULD | 9111 §4.3.1 | test | "SHOULD send the Last-Modified value (using If-Modified-Since) if the
	request is not for a subrange"
9111-4.3.1-subrange | MAY | 9111 §4.3.1 | n/a: ranges are bypassed (§3.3), so a subrange is never validated | "MAY
	send the Last-Modified value (using If-Unmodified-Since or If-Range) if the request is for a subrange"

# RFC 9111 §4.3.2 Handling a Received Validation Request
9111-4.3.2-evaluate | SHOULD | 9111 §4.3.2 | test | "the cache SHOULD evaluate any applicable conditional header field
	preconditions received in that request"
9111-4.3.2-origin-only | MUST NOT | 9111 §4.3.2 | test | "A cache MUST NOT evaluate conditional header fields that
	only apply to an origin server"
9111-4.3.2-unsatisfiable | MUST NOT | 9111 §4.3.2 | test | "A cache MUST NOT evaluate ... occur in a request with
	semantics that cannot be satisfied with a cached response"
9111-4.3.2-no-stored | MUST NOT | 9111 §4.3.2 | test | "A cache MUST NOT evaluate ... occur in a request with a target
	resource for which it has no stored responses"
9111-4.3.2-ims-date | SHOULD | 9111 §4.3.2 | test | "a cache SHOULD use the stored response's Date field value"
9111-4.3.2-union | MAY | 9111 §4.3.2 | n/a: MAY not taken: client ETags are never merged into the cache's
	If-None-Match | "the cache MAY combine the received list with a list of entity tags from its own stored set of
	responses"
9111-4.3.2-union-partial | MUST NOT | 9111 §4.3.2 | n/a: no ETag union is ever sent, and partial responses are never
	stored | "the cache MUST NOT include its entity tag in the union unless the request is for a range"
9111-4.3.2-union-304 | MUST | 9111 §4.3.2 | n/a: no ETag union is ever sent, so a 304 never carries an ETag outside a
	client's list | "the cache MUST generate a 200 (OK) response for the client by reusing its corresponding stored
	response"

# RFC 9111 §4.3.3 Handling a Validation Response
9111-4.3.3-full | MUST | 9111 §4.3.3 | test | "the cache MUST use the full response to satisfy the request"
9111-4.3.3-store-full | MAY | 9111 §4.3.3 | test | "The cache MAY store such a full response, subject to its
	constraints"

# RFC 9111 §4.3.4 Freshening Stored Responses upon Validation
# The weak-validator and no-validator branches carry no BCP 14 keyword and are tracked under the ids below.
9111-4.3.4-strong | MUST NOT | 9111 §4.3.4 | test | "then the cache MUST NOT use the new response to update any stored
	responses"
9111-4.3.4-update | MUST | 9111 §4.3.4 | test | "the cache MUST update its header fields with the header fields
	provided in the 304 (Not Modified) response"

# RFC 9111 §4.3.5 Freshening Responses with HEAD
9111-4.3.5-head | SHOULD | 9111 §4.3.5 | test | "the cache SHOULD update or invalidate each of its stored GET
	responses that could have been chosen"
9111-4.3.5-update | SHOULD | 9111 §4.3.5 | test | "the cache SHOULD update the stored response as described below"
9111-4.3.5-stale | SHOULD | 9111 §4.3.5 | test | "otherwise, the cache SHOULD consider the stored response to be
	stale"
9111-4.3.5-head-fields | MUST | 9111 §4.3.5 | test | "the cache MUST use the header fields provided in the HEAD
	response to update the stored response"

# RFC 9111 §4.4 Invalidating Stored Responses
9111-4.4-target | MUST | 9111 §4.4 | test | "A cache MUST invalidate the target URI (Section 7.1 of [HTTP]) when it
	receives a non-error status code"
9111-4.4-other-uris | MAY | 9111 §4.4 | test | "A cache MAY invalidate other URIs when it receives a non-error status
	code in response to an unsafe request method"
9111-4.4-cross-origin | MUST NOT | 9111 §4.4 | test | "a cache MUST NOT trigger an invalidation under these conditions
	if the origin ... differs from that of the target URI"

# RFC 9111 §5.1 Age
9111-5.1-age-list | SHOULD | 9111 §5.1 | test | "a cache encountering a message with a list-based Age field value
	SHOULD use the first member of the field value"
9111-5.1-age-invalid | SHOULD | 9111 §5.1 | test | "a cache SHOULD ignore the field"

# RFC 9111 §5.2 Cache-Control
9111-5.2-pass-through | MUST | 9111 §5.2 | test | "A proxy, whether or not it implements a cache, MUST pass cache
	directives through in forwarded messages"

# RFC 9111 §5.2.1 Request Directives
9111-5.2.1-optional | MAY | 9111 §5.2.1 | test | "caches MAY implement them, but are not required to"
9111-5.2.1.1-quoted | MUST NOT | 9111 §5.2.1.1 | n/a: binds senders; this cache generates no Cache-Control | "A sender
	MUST NOT generate the quoted-string form."
9111-5.2.1.2-quoted | MUST NOT | 9111 §5.2.1.2 | n/a: binds senders; this cache generates no Cache-Control | "A sender
	MUST NOT generate the quoted-string form."
9111-5.2.1.3-quoted | MUST NOT | 9111 §5.2.1.3 | n/a: binds senders; this cache generates no Cache-Control | "A sender
	MUST NOT generate the quoted-string form."
9111-5.2.1.5-no-store | MUST NOT | 9111 §5.2.1.5 | test | "a cache MUST NOT store any part of either this request or
	any response to it"
9111-5.2.1.5-non-volatile | MUST NOT | 9111 §5.2.1.5 | test | "the cache MUST NOT intentionally store the information in
	non-volatile storage"
9111-5.2.1.5-volatile | MUST | 9111 §5.2.1.5 | n/a: nothing is retained, because requests with no-store skip every
	write path and body capture | "MUST make a best-effort attempt to remove the information from volatile storage as
	promptly as possible"
9111-5.2.1.7-only-if-cached | SHOULD | 9111 §5.2.1.7 | test | "Caches that honor this request directive SHOULD, upon
	receiving it, respond with either a stored response"

# RFC 9111 §5.2.2 Response Directives
9111-5.2.2-obey | MUST | 9111 §5.2.2 | test | "A cache MUST obey the Cache-Control directives defined in this section"
9111-5.2.2.1-quoted | MUST NOT | 9111 §5.2.2.1 | n/a: binds senders; this cache generates no Cache-Control | "A sender
	MUST NOT generate the quoted-string form."
9111-5.2.2.2-stale-reuse | MUST NOT | 9111 §5.2.2.2 | test | "a cache MUST NOT reuse that response to satisfy another
	request until it has been successfully validated by the origin"
9111-5.2.2.2-no-ignore | MUST NOT | 9111 §5.2.2.2 | test | "In all circumstances, a cache MUST NOT ignore the
	must-revalidate directive"
9111-5.2.2.2-disconnected | MUST | 9111 §5.2.2.2 | test | "if a cache is disconnected, the cache MUST generate an
	error response rather than reuse the stale response"
9111-5.2.2.2-504 | SHOULD | 9111 §5.2.2.2 | deviation: the cache generates no error response; RoundTrip returns
	the transport error, and the caller picks the status (httputil.ReverseProxy sends 502) | "The generated status code
	SHOULD be 504 (Gateway Timeout) unless another error status code is more applicable"
9111-5.2.2.3-also-no-store | SHOULD | 9111 §5.2.2.3 | n/a: binds origin servers | "A response that contains the
	must-understand directive SHOULD also contain the no-store directive"
9111-5.2.2.3-ignore-no-store | SHOULD | 9111 §5.2.2.3 | test | "the cache SHOULD ignore the no-store directive if it
	understands and implements the status code's caching requirements"
9111-5.2.2.4-no-cache | MUST NOT | 9111 §5.2.2.4 | test | "the response MUST NOT be used to satisfy any other request
	without forwarding it for validation"
9111-5.2.2.4-qualified | MAY | 9111 §5.2.2.4 | n/a: MAY not taken: a qualified no-cache is treated as unqualified |
	"MAY use the response to satisfy a subsequent request, subject to any other restrictions on caching"
9111-5.2.2.4-token-form | SHOULD NOT | 9111 §5.2.2.4 | n/a: binds senders; this cache generates no Cache-Control | "A
	sender SHOULD NOT generate the token form"
9111-5.2.2.5-no-store | MUST NOT | 9111 §5.2.2.5 | test | "a cache MUST NOT store any part of either the immediate
	request or the response"
9111-5.2.2.5-no-reuse | MUST NOT | 9111 §5.2.2.5 | test | "and MUST NOT use the response to satisfy any other request"
9111-5.2.2.5-non-volatile | MUST NOT | 9111 §5.2.2.5 | test | "the cache MUST NOT intentionally store the information in
	non-volatile storage"
9111-5.2.2.5-volatile | MUST | 9111 §5.2.2.5 | n/a: nothing is retained: a no-store response is never stored,
	buffered, or merged into a stored response | "MUST make a best-effort attempt to remove the information from volatile
	storage as promptly as possible"
9111-5.2.2.6-no-transform | MUST NOT | 9111 §5.2.2.6 | test | "an intermediary (regardless of whether it implements a
	cache) MUST NOT transform the content"
9111-5.2.2.7-shared | MUST NOT | 9111 §5.2.2.7 | test | "a shared cache MUST NOT store the response (i.e., the
	response is intended for a single user)"
9111-5.2.2.7-private-cache | MAY | 9111 §5.2.2.7 | test | "a private cache MAY store the response, subject to the
	constraints defined in Section 3"
9111-5.2.2.7-qualified | MUST NOT | 9111 §5.2.2.7 | test | "a shared cache MUST NOT store the listed header fields if
	they are present in the original response"
9111-5.2.2.7-remainder | MAY | 9111 §5.2.2.7 | n/a: MAY not taken: a qualified private is treated as unqualified, so
	nothing is stored | "MAY store the remainder of the response message without those header fields"
9111-5.2.2.7-token-form | SHOULD NOT | 9111 §5.2.2.7 | n/a: binds senders; this cache generates no Cache-Control | "A
	sender SHOULD NOT generate the token form"
9111-5.2.2.8-stale-reuse | MUST NOT | 9111 §5.2.2.8 | test | "a shared cache MUST NOT reuse that response to satisfy
	another request until it has been successfully validated"
9111-5.2.2.9-public | MAY | 9111 §5.2.2.9 | test | "a cache MAY store the response even if it would otherwise be
	prohibited, subject to the constraints defined in Section 3"
9111-5.2.2.10-stale-reuse | MUST NOT | 9111 §5.2.2.10 | test | "A shared cache MUST NOT reuse a stale response with
	s-maxage to satisfy another request"
9111-5.2.2.10-quoted | MUST NOT | 9111 §5.2.2.10 | n/a: binds senders; this cache generates no Cache-Control | "A
	sender MUST NOT generate the quoted-string form."

# RFC 9111 §5.2.3 Extension Directives
9111-5.2.3-ignore-unknown | MUST | 9111 §5.2.3 | test | "A cache MUST ignore unrecognized cache directives."

# RFC 9111 §5.2.4 Cache Directive Registry
9111-5.2.4-registration | MUST | 9111 §5.2.4 | n/a: binds IANA registrations, not caches | "A registration MUST
	include the following fields"

# RFC 9111 §5.3 Expires
9111-5.3-invalid-date | MUST | 9111 §5.3 | test | "A cache recipient MUST interpret invalid date formats"
9111-5.3-ignore-max-age | MUST | 9111 §5.3 | test | "with the max-age directive ... a recipient MUST ignore the
	Expires header field"
9111-5.3-ignore-s-maxage | MUST | 9111 §5.3 | test | "if a response includes the s-maxage directive ... a shared cache
	recipient MUST ignore the Expires header field"
9111-5.3-no-clock | MUST NOT | 9111 §5.3 | n/a: binds origin servers | "An origin server without a clock ... MUST NOT
	generate an Expires header field"

# RFC 9111 §5.4 Pragma
# No BCP 14 keyword. Pragma is deprecated: this cache neither honors nor generates it.

# RFC 9111 §5.5 Warning
# No BCP 14 keyword. Warning is obsoleted: this cache neither honors nor generates it.

# RFC 9110 §5.6.7 Date/Time Formats
9110-5.6.7-accept-formats | MUST | 9110 §5.6.7 | test | "A recipient that parses a timestamp value in an HTTP field
	MUST accept all three HTTP-date formats"
9110-5.6.7-imf-fixdate | MUST | 9110 §5.6.7 | test | "the sender MUST generate those timestamps in the IMF-fixdate
	format"
9110-5.6.7-no-whitespace | MUST NOT | 9110 §5.6.7 | test | "A sender MUST NOT generate additional whitespace in an
	HTTP-date"
9110-5.6.7-rfc850-year | MUST | 9110 §5.6.7 | test | "which uses a two-digit year, MUST interpret a timestamp that
	appears to be more than 50 years in the future"

# RFC 9110 §6.6.1 Date
9110-6.6.1-date-approx | SHOULD | 9110 §6.6.1 | test | "A sender that generates a Date header field SHOULD generate
	its field value as the best available approximation"
9110-6.6.1-add-date | MUST | 9110 §6.6.1 | test | "A recipient with a clock that receives a response message without a
	Date header field MUST record the time"
9110-6.6.1-invalid-date | MAY | 9110 §6.6.1 | test | "A recipient with a clock that receives a response with an
	invalid Date header field value MAY replace that value"

# RFC 9110 §7.6.1 Connection
9110-7.6.1-connection-fields | MUST | 9110 §7.6.1 | test | "Intermediaries MUST parse a received Connection header
	field before a message is forwarded"
9110-7.6.1-hop-by-hop | SHOULD | 9110 §7.6.1 | test | "intermediaries SHOULD remove or replace fields that are known
	to require removal before forwarding"
9110-7.6.1-connection-option | MUST NOT | 9110 §7.6.1 | n/a: this cache generates no Connection header | "A sender
	MUST NOT send a connection option corresponding to a field that is intended for all recipients"
9110-7.6.1-list-fields | MUST | 9110 §7.6.1 | n/a: this cache generates no connection-specific fields | "the sender
	MUST list the corresponding field name within the Connection header field"

# RFC 9110 §7.7 Message Transformations
9110-7.7-add-domain | MAY | 9110 §7.7 | n/a: MAY not taken: the cache never rewrites the target URI | "it MAY add its
	own domain to the host name it received when forwarding the request"
9110-7.7-host-name | MUST NOT | 9110 §7.7 | test | "A proxy MUST NOT change the host name if the target URI contains a
	fully qualified domain name"
9110-7.7-path-query | MUST NOT | 9110 §7.7 | test | "A proxy MUST NOT modify the ... parts of the received target URI
	when forwarding it to the next inbound server"
9110-7.7-no-transform | MUST NOT | 9110 §7.7 | test | "A proxy MUST NOT transform the content (Section 6.4) of a
	response message that contains a no-transform cache directive"
9110-7.7-transform | MAY | 9110 §7.7 | n/a: MAY not taken: bodies are stored and served byte-for-byte | "A proxy MAY
	transform the content of a message that does not contain a no-transform cache directive"
9110-7.7-metadata | SHOULD NOT | 9110 §7.7 | test | "A proxy SHOULD NOT modify header fields that provide information
	about the endpoints of the communication chain"

# RFC 9110 §8.8.1 Weak versus Strong
# The only keyword (an origin server SHOULD change a weak entity tag) binds origin servers, so it is not tracked.

# RFC 9110 §8.8.2.2 Last-Modified Comparison
# No BCP 14 keyword. The rule that a Last-Modified is strong when Date is at least one second later is prose only.

# RFC 9110 §8.8.3.2 ETag Comparison
# No BCP 14 keyword.

# RFC 9110 §9.3.1 GET
9110-9.3.1-get-reuse | MAY | 9110 §9.3.1 | test | "a cache MAY use it to satisfy subsequent GET and HEAD requests
	unless otherwise indicated by the Cache-Control"

# RFC 9110 §9.3.2 HEAD
9110-9.3.2-no-content | MUST NOT | 9110 §9.3.2 | test | "The HEAD method is identical to GET except that the server
	MUST NOT send content in the response"
9110-9.3.2-same-headers | SHOULD | 9110 §9.3.2 | test | "The server SHOULD send the same header fields in response to
	a HEAD request as it would have sent"
9110-9.3.2-head-reuse | MAY | 9110 §9.3.2 | n/a: MAY not taken: HEAD responses are never stored; HEAD is served from
	stored GET responses | "a cache MAY use it to satisfy subsequent HEAD requests unless otherwise indicated by the
	Cache-Control"

# RFC 9110 §13.1.1 If-Match
9110-13.1.1-ignore | MAY | 9110 §13.1.1 | test | "A cache or intermediary MAY ignore If-Match because its
	interoperability features are only necessary"

# RFC 9110 §13.1.2 If-None-Match
9110-13.1.2-weak | MUST | 9110 §13.1.2 | test | "A recipient MUST use the weak comparison function when comparing
	entity tags for If-None-Match"
9110-13.1.2-client-inm | SHOULD | 9110 §13.1.2 | test | "the client SHOULD generate an If-None-Match header field
	containing a list of those entity tags"

# RFC 9110 §13.1.3 If-Modified-Since
9110-13.1.3-ims-inm | MUST | 9110 §13.1.3 | test | "A recipient MUST ignore If-Modified-Since if the request contains
	an If-None-Match header field"
9110-13.1.3-ims-invalid | MUST | 9110 §13.1.3 | test | "A recipient MUST ignore the If-Modified-Since header field if
	the received field value is not a valid HTTP-date"
9110-13.1.3-ims-list | MUST | 9110 §13.1.3 | test | "A recipient MUST ignore the If-Modified-Since header field if ...
	the field value has more than one member"
9110-13.1.3-ims-method | MUST | 9110 §13.1.3 | test | "A recipient MUST ignore the If-Modified-Since header field if
	... the request method is neither GET nor HEAD"
9110-13.1.3-ims-no-date | MUST | 9110 §13.1.3 | n/a: the cache always has a date: Last-Modified, else Date, else the
	receive time (9111 §4.3.2) | "A recipient MUST ignore the If-Modified-Since header field if the resource does not
	have a modification date available"
9110-13.1.3-origin-clock | MUST | 9110 §13.1.3 | test | "A recipient MUST interpret an If-Modified-Since field value's
	timestamp in terms of the origin server's clock"

# RFC 9110 §13.1.4 If-Unmodified-Since
9110-13.1.4-ignore | MAY | 9110 §13.1.4 | test | "A cache or intermediary MAY ignore If-Unmodified-Since because its
	interoperability features"
9110-13.1.4-ius-if-match | MUST | 9110 §13.1.4 | n/a: the cache never evaluates If-Unmodified-Since; such requests
	bypass it (9111 §4.3.2) | "A recipient MUST ignore If-Unmodified-Since if the request contains an If-Match header
	field"
9110-13.1.4-ius-invalid | MUST | 9110 §13.1.4 | n/a: the cache never evaluates If-Unmodified-Since; such requests
	bypass it (9111 §4.3.2) | "A recipient MUST ignore the If-Unmodified-Since header field if the received field value
	is not a valid HTTP-date"
9110-13.1.4-ius-no-date | MUST | 9110 §13.1.4 | n/a: the cache never evaluates If-Unmodified-Since; such requests
	bypass it (9111 §4.3.2) | "A recipient MUST ignore the If-Unmodified-Since header field if the resource does not have
	a modification date available"
9110-13.1.4-ius-clock | MUST | 9110 §13.1.4 | n/a: the cache never evaluates If-Unmodified-Since; such requests bypass
	it (9111 §4.3.2) | "A recipient MUST interpret an If-Unmodified-Since field value's timestamp in terms of the origin
	server's clock"

# RFC 9110 §13.1.5 If-Range
9110-13.1.5-no-range | MUST | 9110 §13.1.5 | n/a: ranges are bypassed (§3.3); If-Range requests are forwarded
	unevaluated | "A server MUST ignore an If-Range header field received in a request that does not contain a Range
	header field"
9110-13.1.5-client-no-range | MUST NOT | 9110 §13.1.5 | n/a: this cache generates no If-Range | "A client MUST NOT
	generate an If-Range header field in a request that does not contain a Range header field"
9110-13.1.5-client-weak | MUST NOT | 9110 §13.1.5 | n/a: this cache generates no If-Range | "A client MUST NOT
	generate an If-Range header field containing an entity tag that is marked as weak"
9110-13.1.5-client-date | MUST NOT | 9110 §13.1.5 | n/a: this cache generates no If-Range | "A client MUST NOT
	generate an If-Range header field containing an HTTP-date unless the client has no entity tag"
9110-13.1.5-evaluate | MUST | 9110 §13.1.5 | n/a: ranges are bypassed (§3.3); If-Range requests are forwarded
	unevaluated | "A server that receives an If-Range header field on a Range request MUST evaluate the condition per
	Section 13.2"
9110-13.1.5-ignore-range | MUST | 9110 §13.1.5 | n/a: ranges are bypassed (§3.3); If-Range requests are forwarded
	unevaluated | "A recipient of an If-Range header field MUST ignore the Range header field if the If-Range condition
	evaluates to false"
9110-13.1.5-process-range | SHOULD | 9110 §13.1.5 | n/a: ranges are bypassed (§3.3); If-Range requests are forwarded
	unevaluated | "Otherwise, the recipient SHOULD process the Range header field as requested"

# RFC 9110 §13.2.1 When to Evaluate
9110-13.2.1-evaluate | MUST | 9110 §13.2.1 | test | "a recipient cache or origin server MUST evaluate received request
	preconditions after it has successfully performed"
9110-13.2.1-non-2xx | MUST | 9110 §13.2.1 | test | "A server MUST ignore all received preconditions if its response to
	the same request without those conditions"
9110-13.2.1-no-eval | MUST NOT | 9110 §13.2.1 | test | "cannot act as a cache for requests on the target resource MUST
	NOT evaluate the conditional request header fields"
9110-13.2.1-forward | MUST | 9110 §13.2.1 | test | "and it MUST forward them if the request is forwarded"
9110-13.2.1-non-selecting | MUST | 9110 §13.2.1 | test | "a server MUST ignore the conditional request header fields
	... when received with a request method that does not involve"

# RFC 9110 §13.2.2 Precedence of Preconditions
9110-13.2.2-order | MUST | 9110 §13.2.2 | test | "A recipient cache or origin server MUST evaluate the request
	preconditions ... in the following order"

# RFC 9110 §15.1 Overview of Status Codes
# No BCP 14 keyword. The heuristically cacheable status list is applied under 9111-3-heuristic-status.

# RFC 9110 §15.4.5 304 Not Modified
9110-15.4.5-generate | MUST | 9110 §15.4.5 | test | "The server generating a 304 response MUST generate any of the
	following header fields that would have been sent"
9110-15.4.5-metadata | SHOULD NOT | 9110 §15.4.5 | test | "a sender SHOULD NOT generate representation metadata other
	than the above listed fields"
9110-15.4.5-forward | SHOULD | 9110 §15.4.5 | test | "the proxy SHOULD forward the 304 response to that client"
`
