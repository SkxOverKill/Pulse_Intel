import "dotenv/config";
import { hashPassword } from "@/lib/auth/password";
import { db } from "@/lib/db";

async function main() {
  const email = "sukeshkumartkd@gmail.com";
  const password = "$uki@Cyvera203S";
  const passwordHash = await hashPassword(password);

  const user = await db.user.upsert({
    where: { email },
    update: { passwordHash, role: "ADMIN", active: true },
    create: { email, name: "Sukesh Kumar", passwordHash, role: "ADMIN" },
  });
  console.log("OK", user.id, user.email, user.role);
  await db.$disconnect();
}

main();
