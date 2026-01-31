CREATE TABLE games (
  id INT AUTO_INCREMENT PRIMARY KEY,

  user_id INT NOT NULL,

  game_name VARCHAR(150) NOT NULL,

  launcher ENUM(
    'Steam',
    'Epic Games',
    'PlayStation Store',
    'Xbox'
  ) NOT NULL,

  game_id VARCHAR(150) NOT NULL,

  game_password VARCHAR(255) NOT NULL,

  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
