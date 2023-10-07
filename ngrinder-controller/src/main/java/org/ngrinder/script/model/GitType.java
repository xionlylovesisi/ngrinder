package org.ngrinder.script.model;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum GitType {
	GITHUB("github"), GITLAB("gitlab");

	private final String value;
}
