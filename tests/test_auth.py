def test_get_current_user_without_token(client):
    response = client.get("/users/me")

    assert response.status_code == 401


def test_get_current_user_with_invalid_token(client):
    response = client.get(
        "/users/me",
        headers={
            "Authorization": "Bearer invalid-token",
        },
    )

    assert response.status_code == 401


def test_get_current_user_with_valid_token(client):
    user_data = {"email": "test-auth@example.com", "password": "TestPassword123!"}

    create_response = client.post("users/", json=user_data)

    assert create_response.status_code == 200

    login_response = client.post("/auth/login", json=user_data)

    assert login_response.status_code == 200

    token = login_response.json()["access_token"]

    response = client.get("/users/me", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    assert response.json()["email"] == user_data["email"]
