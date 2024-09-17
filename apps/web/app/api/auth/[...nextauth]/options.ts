import bcrypt from "bcrypt";
import db from "@repo/db/client";
import CredentialsProvider from "next-auth/providers/credentials";
import { signinValidation } from "../../../../validations/auth.validation";
import { ZodError } from "zod";

export const authOptions = {
  providers: [
    CredentialsProvider({
      name: "Credentials",
      credentials: {
        phone: { label: "Phone number", type: "text", placeholder: "Enter your Phone number" },
        password: { label: "Password", type: "password", placeholder: "Enter your Password" }
      },
      async authorize(credentials) {
        try {
          // Zod validation
          const parsedData = signinValidation.parse({
            phone: credentials?.phone,
            password: credentials?.password
          });

          // Check if the user exists in the database
          const existingUser = await db.user.findFirst({
            where: { number: parsedData.phone }
          });

          if (existingUser) {
            const passwordValidation = await bcrypt.compare(parsedData.password, existingUser.password);
            if (passwordValidation) {
              return {
                id: existingUser.id.toString(),
                name: existingUser.username,
                email: existingUser.number
              };
            }
            return null;
          }

          // If user doesn't exist, create a new user
          const hashedPassword = await bcrypt.hash(parsedData.password, 10);
          const newUser = await db.user.create({
            data: {
              number: parsedData.phone,
              password: hashedPassword,
              username: '',
              email: '',
            }
          });

          return {
            id: newUser.id.toString(),
            username: newUser.username,
            email: newUser.number
          };

        } catch (error) {
          if (error instanceof ZodError) {
            console.error("Validation error:", error.errors);
            return null;
          }
          console.error("Unexpected error during authorization:", error);
          return null;
        }
      }
    })
  ],
  secret: process.env.JWT_SECRET || "secret",
  callbacks: {
    async session({ token, session }: { token: any, session: any }) { // Improved typing
      if (token?.sub) {
        session.user.id = token.sub;
      }
      return session;
    }
  }
};
