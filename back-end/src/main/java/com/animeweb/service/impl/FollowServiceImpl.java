package com.animeweb.service.impl;

import com.animeweb.dto.movie.FollowDTO;
import com.animeweb.entities.Follow;
import com.animeweb.mapper.FollowMapper;
import com.animeweb.repository.FollowRepository;
import com.animeweb.service.FollowService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class FollowServiceImpl implements FollowService {
    @Autowired
    private FollowRepository followRepository;

    @Override
    public FollowDTO addFollow(Follow follow) {
        Follow existingFollow = this.followRepository.findFollowByUserIdAndMovieId(follow.getMovie().getId(), follow.getUserId().getId());

        if (existingFollow == null) {
            Follow savedFollow = this.followRepository.save(follow);
            return convertToDTO(savedFollow);
        } else {
            return updateFollow(follow);
        }
    }

    private FollowDTO convertToDTO(Follow follow) {
        return FollowDTO.builder()
                .id(follow.getId())
                .followAt(follow.getFollowAt())
                .userId(follow.getUserId().getId())
                .movieId(follow.getMovie().getId())
                .status(follow.getStatus())
                .build();
    }
    @Override
    public FollowDTO updateFollow(Follow follow) {
        Follow existingFollow = this.followRepository.findFollowByUserIdAndMovieId(follow.getMovie().getId(), follow.getUserId().getId());
        if (existingFollow != null) {
            existingFollow.setFollowAt(existingFollow.getFollowAt());
            existingFollow.setStatus(!existingFollow.getStatus());
            Follow updatedFollow = this.followRepository.save(existingFollow);
            return convertToDTO(updatedFollow);
        } else {
            throw new RuntimeException("Follow entity not found for update");
        }
    }

    @Override
    public FollowDTO findFollowByIdUserAndIdMovie(Long movieId,Long userId) {
        Follow f = followRepository.findFollowByUserIdAndMovieId(movieId,userId);
        return f != null ? FollowMapper.mapToFollowDTO(f) : null;
    }


}