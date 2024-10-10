package com.demoapp.validators;

public class InputValidator {

    public boolean isValidEmail(String email) {
        String emailRegex = "^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$";

        return email != null && email.matches(emailRegex);
    }

    public boolean isValidPassword(String password) {
        return password != null && password.length() > 5;
    }

    public boolean isValidUsername(String username) {
        return username != null && !username.isEmpty();
    }

    public boolean validateUserInput(String username, String email, String password) {
        return isValidUsername(username) && isValidEmail(email) && isValidPassword(password);
    }
}