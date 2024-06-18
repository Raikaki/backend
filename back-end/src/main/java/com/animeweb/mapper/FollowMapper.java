package com.animeweb.mapper;

import com.animeweb.dto.movie.FollowDTO;
import com.animeweb.entities.Follow;
public class FollowMapper {
    public static FollowDTO mapToFollowDTO(Follow follow){
        return new FollowDTO(
                follow.getId(),follow.getFollowAt(),follow.getStatus(),follow.getUserId().getId(),follow.getMovie().getId());
    }
}