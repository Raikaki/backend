package com.animeweb.controller.admin;

import com.animeweb.dto.genre.GenreDTO;
import com.animeweb.entities.Genre;
import com.animeweb.mapper.GenreMapper;
import com.animeweb.mapper.RoleMapper;
import com.animeweb.service.GenreService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

@RestController
@RequestMapping("/admin/genres")
public class AdminGenreController {
    @Autowired
    GenreService genreService;
    @GetMapping()
    @PreAuthorize("hasAuthority('view_genres') or hasRole('ADMIN')")
    public ResponseEntity<List<GenreDTO>> getAdminGenres(){
        return new ResponseEntity<>(genreService.getAllGenre(), HttpStatus.OK);
    }
    @PostMapping
    @PreAuthorize("hasAuthority('add_genre') or hasRole('ADMIN')")
    public ResponseEntity<GenreDTO> addGenre(@RequestBody GenreDTO genreDTO){
        if(genreService.existDescription(genreDTO.getDescription())) throw new ResponseStatusException(HttpStatus.NOT_ACCEPTABLE,"Thể loại đã tồn tại");
        Genre genre = new Genre();
        genre.setDescription(genreDTO.getDescription());
        genreService.save(genre);
        return new ResponseEntity<>(GenreMapper.mapToGenreDto(genre),HttpStatus.CREATED);
    }
    @PutMapping("/{genreId}")
    @PreAuthorize("hasAuthority('edit_genre') or hasRole('ADMIN')")
    public ResponseEntity<GenreDTO> editGenre(@PathVariable Long genreId,@RequestBody GenreDTO genreDTO){
        Genre genre = genreService.getById(genreId);
        if(genre==null) throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Thể loại không tồn tại!");
        if(genreService.existDescription(genreDTO.getDescription())) throw new ResponseStatusException(HttpStatus.NOT_ACCEPTABLE,"Thể loại đã tồn tại");
        genre.setDescription(genreDTO.getDescription());
        genreService.save(genre);
        return new ResponseEntity<>(GenreMapper.mapToGenreDto(genre),HttpStatus.CREATED);
    }
    @DeleteMapping("/{genreId}")
    @PreAuthorize("hasAuthority('delete_genre') or hasRole('ADMIN')")
    public ResponseEntity<String> deleteGenre(@PathVariable Long genreId){
        Genre genre = genreService.getById(genreId);
        if(genre==null) throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Thể loại không tồn tại!");
        genre.setStatus(false);
        genreService.save(genre);
        return new ResponseEntity<>("Đã xóa thành công",HttpStatus.CREATED);
    }

}
