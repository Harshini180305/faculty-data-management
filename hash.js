const bcrypt = require('bcryptjs');

const passwords = ['cse123', 'csm123', 'csd123', 'ai123'];

passwords.forEach(password => {
  bcrypt.hash(password, 10, (err, hash) => {
    if (err) {
      console.error(`Error hashing ${password}:`, err);
      return;
    }
    console.log(`Hashed password for ${password}: ${hash}`);
  });
});