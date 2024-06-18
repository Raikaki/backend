package com.animeweb.security;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class IntrospectResponse {
    private boolean valid;
}
