// macropad.apk をパスワードで暗号化して macropad.apk.enc と macropad.apk.check.json を生成する。
// 使い方: node encrypt-apk.mjs [入力APK] [出力ファイル]
// .enc 形式: "MPENC1"(6) | iterations(4, BE) | salt(16) | iv(12) | ciphertext+tag
// .check.json: 同じ salt/鍵で空データを暗号化した認証タグ。ページが本体取得前にパスワードを確認するために使う。
// 2ファイルは必ず同時に生成・コミットすること。index.html の復号処理と形式を合わせること。
import { readFileSync, writeFileSync } from "node:fs";
import { randomBytes, pbkdf2Sync, createCipheriv } from "node:crypto";
import readline from "node:readline";

const ITERATIONS = 600000;
const input = process.argv[2] ?? "macropad.apk";
const output = process.argv[3] ?? "macropad.apk.enc";
const checkOutput = output.replace(/\.enc$/, "") + ".check.json";

function askHidden(query) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    rl._writeToOutput = (s) => {
      if (s.startsWith(query)) rl.output.write(query);
    };
    rl.question(query, (answer) => {
      rl.close();
      process.stdout.write("\n");
      resolve(answer);
    });
  });
}

const password = process.env.APK_PASSWORD ?? (await askHidden("パスワード: "));
if (!process.env.APK_PASSWORD) {
  const confirm = await askHidden("パスワード(確認): ");
  if (password !== confirm) {
    console.error("パスワードが一致しません。");
    process.exit(1);
  }
}
if (password.length < 12) {
  console.error("パスワードは12文字以上にしてください（暗号文は公開されるため総当たり対策が必要です）。");
  process.exit(1);
}

const plain = readFileSync(input);
const salt = randomBytes(16);
const iv = randomBytes(12);
const key = pbkdf2Sync(Buffer.from(password, "utf8"), salt, ITERATIONS, 32, "sha256");

const cipher = createCipheriv("aes-256-gcm", key, iv);
const encrypted = Buffer.concat([cipher.update(plain), cipher.final(), cipher.getAuthTag()]);

const header = Buffer.alloc(10);
header.write("MPENC1", 0, "ascii");
header.writeUInt32BE(ITERATIONS, 6);

const encBytes = Buffer.concat([header, salt, iv, encrypted]);
writeFileSync(output, encBytes);

const checkIv = randomBytes(12);
const checkCipher = createCipheriv("aes-256-gcm", key, checkIv);
checkCipher.final();
writeFileSync(checkOutput, JSON.stringify({
  iterations: ITERATIONS,
  salt: salt.toString("base64"),
  checkIv: checkIv.toString("base64"),
  check: checkCipher.getAuthTag().toString("base64"),
  size: encBytes.length,
}, null, 2) + "\n");

console.log(`${output} を生成しました (${plain.length} bytes -> ${encBytes.length} bytes)`);
console.log(`${checkOutput} を生成しました`);
