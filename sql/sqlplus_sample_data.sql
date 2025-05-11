
INSERT INTO URL (url_pattern) VALUES ('www.naver.com');
INSERT INTO URL (url_pattern) VALUES ('www.example.com');


INSERT INTO Policy (policy_name, policy_id) VALUES ('Default Policy', 1);

INSERT INTO User (user_id, user_pw, user_name, user_phone, user_email, policy_id) VALUES ('user001', '7110eda4d09e062aa5e4a390b0a572ac0d2c0220', 'Alice', '010-1111-2222', 'alice@example.com', 1);

INSERT INTO Policy_URL (policy_id, url_id) VALUES (1, 1);
INSERT INTO Policy_URL (policy_id, url_id) VALUES (1, 2);
