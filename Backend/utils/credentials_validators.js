import validator from "validator";

export const credentialChecker = (name, email, password) => {
  const error = {};

  if (!name || !email || !password) {
    error.msg = "Please enter all credentials";
  }

  if (!validator.isAlpha(name, "en-US", { ignore: " " })) {
    error.name = "Name must only contain letters";
  }

  if (!validator.isEmail(email)) {
    error.email = "Invalid email format";
  }

  const strongPassword = validator.isStrongPassword(password, {
    minLength: 10,
    minLowercase: 2,
    minUppercase: 1, // ✅ Changed from 2 to 1
    minNumbers: 1,
    minSymbols: 1,
  });

  if (!strongPassword) {
    error.password =
      "Password must have 10+ chars, 1 uppercase, 2 lowercase, 1 number, 1 special char";
  }

  return {
    isValid: Object.keys(error).length === 0,
    error,
  };
};
