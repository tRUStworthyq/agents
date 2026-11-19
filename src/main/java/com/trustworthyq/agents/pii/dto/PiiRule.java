package com.trustworthyq.agents.pii.dto;

import java.util.regex.Pattern;

public enum PiiRule {
    EMAIL("[A-Za-z0-9_%+.-]{1,64}@[A-Za-z0-9.-]{1,189}\\.[A-Za-z]{2,63}", "regex"),
    PHONE_RU("(?:\\+7|8)[ -]?\\(?[3489]\\d{2}\\)?[ -]?\\d{3}[ -]?\\d{2}[ -]?\\d{2}", "regex"),
    SNILS("\\d{3}[ -]?\\d{3}[ -]?\\d{3}[ -]?\\d{2}", "checksum"),
    INN_12("\\d{12}", "checksum"),
    PASSPORT_RU("\\d{2} ?\\d{2}[ -]?\\d{6}", "context");

    private static final Pattern PASSPORT_CONTEXT =
            Pattern.compile("(?iu)(?:паспорт|passport|серия|выдан)");

    private final Pattern pattern;
    private final String method;

    PiiRule(String expression, String method) {
        String boundary = name().equals("EMAIL") ? "[\\p{L}\\p{N}_.%+@-]" : "[\\p{L}\\p{N}]";
        this.pattern = Pattern.compile("(?<!" + boundary + ")(?:" + expression + ")(?!" + boundary + ")");
        this.method = method;
    }

    public Pattern pattern() {
        return pattern;
    }

    public String method() {
        return method;
    }

    public boolean matches(String value) {
        return switch (this) {
            case EMAIL -> !value.contains("..") && !value.startsWith(".")
                    && !value.contains(".@") && validDomain(value.substring(value.indexOf('@') + 1));
            case PHONE_RU -> value.contains("(") == value.contains(")");
            case SNILS -> validSnils(value.replaceAll("[ -]", ""));
            case INN_12 -> validInn(value);
            case PASSPORT_RU -> true;
        };
    }

    public boolean requiresReview(CharSequence context) {
        return this == PASSPORT_RU && !PASSPORT_CONTEXT.matcher(context).find();
    }

    private static boolean validDomain(String domain) {
        for (String label : domain.split("\\.")) {
            if (label.isEmpty() || label.length() > 63 || label.startsWith("-") || label.endsWith("-")) {
                return false;
            }
        }
        return true;
    }

    private static boolean validSnils(String value) {
        int number = Integer.parseInt(value.substring(0, 9));
        if (number <= 1001998) {
            return false;
        }
        int sum = 0;
        for (int i = 0; i < 9; i++) {
            sum += (value.charAt(i) - '0') * (9 - i);
        }
        return sum % 101 % 100 == Integer.parseInt(value.substring(9));
    }

    private static boolean validInn(String value) {
        return !value.startsWith("00") && digit(value, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8)
                && digit(value, 3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8);
    }

    private static boolean digit(String value, int... weights) {
        int sum = 0;
        for (int i = 0; i < weights.length; i++) {
            sum += weights[i] * (value.charAt(i) - '0');
        }
        return sum % 11 % 10 == value.charAt(weights.length) - '0';
    }
}
