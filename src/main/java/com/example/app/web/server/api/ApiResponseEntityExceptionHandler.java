package com.example.app.web.server.api;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

/**
 * A {@link ResponseEntityExceptionHandler}.
 */
@ControllerAdvice
public class ApiResponseEntityExceptionHandler extends ResponseEntityExceptionHandler {
	@ExceptionHandler(WebClientResponseException.class)
	public ResponseEntity<Object> handleWebClientResponseException(WebClientResponseException ex, WebRequest request) {
		return ResponseEntity.status(ex.getStatusCode()).body(ex.getResponseBodyAsString());
	}
}
