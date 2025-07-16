import validator from "validator";

export const credentialChecker = (email, name, password) => {
  const error = {};
  name = validator.trim(name);
  email = validator.normalizeEmail(email);
  name = validator.escape(name);
  if (!name || !email || !password) {
    error.msg = "please enter the credentials don't keep them empty";
  }

  if (!validator.isAlpha(name, "en-IN", { ignore: " " })) {
    error.name = "you are entering the wrong name";
  }
  if (!validator.isEmail(email)) {
    error.email = "you have given invalid email please provide real one";
  }
  const strongPassword = validator.isStrongPassword(password, {
    minLength: 10,
    minLowercase: 2,
    minUppercase: 2,
    minNumbers: 1,
    minSymbols: 1,
  });

  if (!strongPassword) {
    error.password = "you have entered invalid password";
  }

  return {
    isValid: Object.keys(error).length === 0,
    error,
  };
};
