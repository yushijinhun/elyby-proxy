function ab2str(buf) {
	return String.fromCharCode.apply(null, new Uint8Array(buf));
}
function str2ab(str) {
	const buf = new Uint8Array(str.length);
	for (let i = 0; i < str.length; i++) {
		buf[i] = str.charCodeAt(i);
	}
	return buf;
}

// Initialize KV storage
const kv = KV_ELYBY_PROXY;
if (kv === undefined) {
	console.log("Error! You must create a KV namespace first.");
	throw new Error("KV namespace not found.");
}

// Gets the signing key pair from KV storage,
// or generates one if it doesn't exist.
// Note that the signing key is stored in DER format.
async function getSigningKeyPair() {
	const storedPrivate = await kv.get("signing_key_private", "arrayBuffer");
	const storedPublic = await kv.get("signing_key_public", "arrayBuffer");
	if (storedPrivate !== null && storedPublic !== null) {
		return {
			privateKey: await crypto.subtle.importKey("pkcs8", storedPrivate, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-1" }, true, ["sign"]),
			publicKey: await crypto.subtle.importKey("spki", storedPublic, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-1" }, true, ["verify"])
		};
	}
	const generatedKeyPair = await crypto.subtle.generateKey(
		{
			name: "RSASSA-PKCS1-v1_5",
			hash: "SHA-1",
			modulusLength: 4096,
			publicExponent: new Uint8Array([1, 0, 1])
		},
		true,
		["sign", "verify"]
	);
	await kv.put("signing_key_private", await crypto.subtle.exportKey("pkcs8", generatedKeyPair.privateKey));
	await kv.put("signing_key_public", await crypto.subtle.exportKey("spki", generatedKeyPair.publicKey));
	return generatedKeyPair;
}

async function getPEMSigningPublicKey() {
	const der = await crypto.subtle.exportKey("spki", (await getSigningKeyPair()).publicKey);
	return `-----BEGIN PUBLIC KEY-----\n${btoa(ab2str(der))}\n-----END PUBLIC KEY-----`;
}

async function signProperty(value) {
	const signature = await crypto.subtle.sign(
		"RSASSA-PKCS1-v1_5",
		(await getPEMSigningPublicKey()).privateKey,
		new TextEncoder().encode(value));
	return btoa(ab2str(signature));
}

// Checks whether the value is properly signed with Mojang's key
async function verifyMojangSignature(value, signature) {
	const mojangPublicKey = await crypto.subtle.importKey(
		"spki",
		str2ab(atob(
			"MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAylB4B6m5lz7jwrcFz6Fd/fnfUhcvlxsTSn5kIK/2aGG1C3kMy4VjhwlxF6BFUSnfxhNswPjh3ZitkBxEAFY25uzkJFRwHwVA9mdwjashXILtR6OqdLXXFVyUPIURLOSWqGNBtb08EN5fMnG8iFLgEJIBMxs9BvF3s3/FhuHyPKiVTZmXY0WY4ZyYqvoKR+XjaTRPPvBsDa4WI2u1zxXMeHlodT3lnCzVvyOYBLXL6CJgByuOxccJ8hnXfF9yY4F0aeL080Jz/3+EBNG8RO4ByhtBf4Ny8NQ6stWsjfeUIvH7bU/4zCYcYOq4WrInXHqS8qruDmIl7P5XXGcabuzQstPf/h2CRAUpP/PlHXcMlvewjmGU6MfDK+lifScNYwjPxRo4nKTGFZf/0aqHCh/EAsQyLKrOIYRE0lDG3bzBh8ogIMLAugsAfBb6M3mqCqKaTMAf/VAjh5FFJnjS+7bE+bZEV0qwax1CEoPPJL1fIQjOS8zj086gjpGRCtSy9+bTPTfTR/SJ+VUB5G2IeCItkNHpJX2ygojFZ9n5Fnj7R9ZnOM+L8nyIjPu3aePvtcrXlyLhH/hvOfIOjPxOlqW+O5QwSFP4OEcyLAUgDdUgyW36Z5mB285uKW/ighzZsOTevVUG2QwDItObIV6i8RCxFbN2oDHyPaO5j1tTaBNyVt8CAwEAAQ=="
		)),
		{ name: "RSASSA-PKCS1-v1_5", hash: "SHA-1" },
		true,
		["verify"]
	);
	const dataBuf = new TextEncoder().encode(value);
	let signatureBuf;
	try {
		signatureBuf = str2ab(atob(signature));
	} catch(e) { // signature can be arbitrary string
		return false;
	}
	return await crypto.subtle.verify("RSASSA-PKCS1-v1_5", mojangPublicKey, signatureBuf, dataBuf);
}

// Ely.by's texture payload doesn't contain valid signature,
// so we have to add one.
async function fixBadSignature(response) {
	if (!response.ok)
		return response;
	const payload = await response.json();
	if (typeof payload !== "object" || !Array.isArray(payload.properties))
		return response;

	for (const property of payload.properties) {
		if (property.name !== "textures" || typeof property.value !== "string")
			continue;
		let signatureValid = false;
		if (typeof property.signature === "string") {
			signatureValid = await verifyMojangSignature(property.value, property.signature);
		}
		if (!signatureValid) {
			// bad signature, we have to re-sign
			const newSignature = await crypto.subtle.sign(
				"RSASSA-PKCS1-v1_5",
				(await getSigningKeyPair()).privateKey,
				new TextEncoder().encode(property.value));
			property.signature = btoa(ab2str(newSignature));
		}
	}

	return new Response(JSON.stringify(payload), {
		status: response.status,
		statusText: response.statusText,
		headers: response.headers
	});
}

// Ely.by's response doesn't include 'user' field,
// this function adds a 'user' field to the response.
async function fixMissingUser(response) {
	if (!response.ok)
		return response;
	const payload = await response.json();
	if (typeof payload !== "object")
		return response;
	if (payload.user !== undefined)
		return response;

	// user id is expected to be stable
	// so we just use selectedProfile.id as user id
	let userid = "8f773e9e422b4687816e065cda471749"; // fallback (randomly-generated)
	if (typeof payload.selectedProfile === "object" && typeof payload.selectedProfile.id === "string") {
		userid = payload.selectedProfile.id.replaceAll("-", "");
	}
	payload.user = {
		id: userid
	};

	return new Response(JSON.stringify(payload), {
		status: response.status,
		statusText: response.statusText,
		headers: response.headers
	});
}

async function forwardRequest(req, upstreamUrl) {
	const forwardUrl = new URL(upstreamUrl);
	forwardUrl.search = new URL(req.url).search;
	return await fetch(forwardUrl, {
		method: req.method,
		headers: req.headers,
		body: req.body
	});
}

function methodNotAllowedResponse(method, allowedMethods) {
	return new Response(
		JSON.stringify({
			error: "Method Not Allowed",
			errorMessage: `${method} is not allowed`
		}),
		{
			status: 405,
			headers: {
				"allowed": allowedMethods.join(", "),
				"content-type": "application/json"
			}
		});
}

const forwardedEndpoints = {
	"/authserver/authenticate": {
		methods: ["POST"],
		target: "https://authserver.ely.by/auth/authenticate",
		postprocess: fixMissingUser
	},
	"/authserver/refresh": {
		methods: ["POST"],
		target: "https://authserver.ely.by/auth/refresh",
		postprocess: fixMissingUser
	},
	"/authserver/validate": {
		methods: ["POST"],
		target: "https://authserver.ely.by/auth/validate"
	},
	"/authserver/signout": {
		methods: ["POST"],
		target: "https://authserver.ely.by/auth/signout"
	},
	"/authserver/invalidate": {
		methods: ["POST"],
		target: "https://authserver.ely.by/auth/invalidate"
	},
	"/sessionserver/session/minecraft/join": {
		methods: ["POST"],
		target: "https://authserver.ely.by/session/join"
	},
	"/sessionserver/session/minecraft/hasJoined": {
		methods: ["GET"],
		target: "https://authserver.ely.by/session/hasJoined",
		postprocess: fixBadSignature
	}
};

const profileUrlRegex = RegExp("^/sessionserver/session/minecraft/profile/([0-9a-f]{32})$");

async function handleRequest(req) {
	const url = new URL(req.url);
	const path = url.pathname;

	if (path === "/") {
		if (req.method !== "GET") {
			return methodNotAllowedResponse(req.method, ["GET"]);
		}
		return new Response(JSON.stringify({
				"meta": {
					"implementationName": "elyby-proxy",
					"implementationVersion": "dev",
					"serverName": "Ely.by",
					"links": {
						"homepage": "https://ely.by/",
						"register": "https://account.ely.by/register"
					},
					"feature.no_mojang_namespace": true
				},
				"skinDomains": [
					"ely.by",
					".ely.by"
				],
				"signaturePublickey": await getPEMSigningPublicKey()
			}),
			{
				status: 200,
				headers: {
					"content-type": "application/json"
				}
			});
	}

	const forwardRule = forwardedEndpoints[path];
	if (forwardRule !== undefined) {
		if (!forwardRule.methods.includes(req.method)) {
			return methodNotAllowedResponse(req.method, forwardRule.methods);
		}
		let response = await forwardRequest(req, forwardRule.target);
		if (forwardRule.postprocess !== undefined) {
			response = await forwardRule.postprocess(response);
		}
		return response;
	}

	const profileUrlMatch = profileUrlRegex.exec(path);
	if (profileUrlMatch !== null) {
		if (req.method !== "GET") {
			return methodNotAllowedResponse(req.method, ["GET"]);
		}
		const uuid = profileUrlMatch[1];
		let response = await forwardRequest(req, `https://authserver.ely.by/session/profile/${uuid}`);
		if (url.searchParams.get("unsigned") === "false") {
			response = await fixBadSignature(response);
		}
		return response;
	}

	return new Response(JSON.stringify({
			error: "Not Found",
			errorMessage: `The path [${path}] is not found`
		}),
		{
			status: 404,
			headers: {
				"content-type": "application/json"
			}
		});
};

addEventListener("fetch", event => {
	try {
		event.respondWith(handleRequest(event.request).catch(e => console.log(e, e.stack)));
	} catch(e) {
		console.log(e, e.stack);	
	}
});
