import crypto from "node:crypto";

export function verifyTelegramData(initData) {
  const token = process.env.BOT_TOKEN;

  if (!token || typeof initData !== "string" || !initData) {
    return null;
  }

  try {
    const params = new URLSearchParams(initData);
    const data = {};

    for (const [key, value] of params.entries()) {
      if (Object.hasOwn(data, key)) {
        return null;
      }

      data[key] = value;
    }

    const receivedHash = data.hash;
    if (!receivedHash || !/^[a-f0-9]{64}$/i.test(receivedHash)) {
      return null;
    }

    delete data.hash;
    data.signature && delete data.signature;

    const checkString = Object.keys(data)
      .sort()
      .map(key => `${key}=${data[key]}`)
      .join("\n");

    const secretKey = crypto
      .createHmac("sha256", "WebAppData")
      .update(token)
      .digest();

    const calculatedHash = crypto
      .createHmac("sha256", secretKey)
      .update(checkString)
      .digest();

    const received = Buffer.from(receivedHash, "hex");

    if (
      received.length !== calculatedHash.length ||
      !crypto.timingSafeEqual(received, calculatedHash)
    ) {
      return null;
    }

    const authDate = Number(data.auth_date);
    const now = Math.floor(Date.now() / 1000);

    if (
      !Number.isSafeInteger(authDate) ||
      authDate > now + 60 ||
      now - authDate > 86400
    ) {
      return null;
    }

    const user = JSON.parse(data.user || "{}");

    if (!Number.isSafeInteger(user.id) || user.id <= 0) {
      return null;
    }

    return user;
  } catch {
    return null;
  }
}
