import validator from "validator";

export const credentialChecker = (name, email, password) => {
  const error = {};

  // ✅ Basic empty checks
  if (!name?.trim() || !email?.trim() || !password?.trim()) {
    error.msg = "Please enter all credentials";
  }

  // ✅ Name: allow spaces and letters
  const nameRegex = /^[A-Za-z\s]+$/;
  if (!nameRegex.test(name)) {
    error.name = "Name must contain only letters and spaces";
  }

  // ✅ Email check
  if (!validator.isEmail(email)) {
    error.email = "Invalid email format";
  }

  // ✅ Password: simple strong password rule (not crazy strict)
  const strongPassword = validator.isStrongPassword(password, {
    minLength: 8,
    minLowercase: 1,
    minUppercase: 1,
    minNumbers: 1,
    minSymbols: 1,
  });

  if (!strongPassword) {
    error.password =
      "Password must have at least 8 chars, 1 uppercase, 1 lowercase, 1 number, 1 special char";
  }

  return {
    isValid: Object.keys(error).length === 0,
    error,
  };
};
