package com.sensetime.fis.senseguard.filter.vo;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * @author guozhiyang_vendor
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class CheckPermissionParam {
	private String action;
	private String uri;
	private String accessToken;
}
