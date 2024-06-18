package com.animeweb.controller.admin;

import com.animeweb.dto.chapter.ChapterDTO;
import com.animeweb.dto.chapter.ChapterRequest;
import com.animeweb.dto.movie.MovieAdd;
import com.animeweb.dto.movie.MovieAdmin;
import com.animeweb.entities.Chapter;
import com.animeweb.entities.Genre;
import com.animeweb.entities.Movie;
import com.animeweb.entities.Serie;
import com.animeweb.mapper.ChapterMapper;
import com.animeweb.mapper.MovieMapper;
import com.animeweb.service.ChapterService;
import com.animeweb.service.GenreService;
import com.animeweb.service.MovieService;
import com.animeweb.service.SerieService;
import com.animeweb.service.ViewService;
import com.animeweb.service.impl.CloudinaryService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/admin/movies")
public class AdminMovieController {
    @Autowired
    MovieService movieService;
    @Autowired
    CloudinaryService uploadService;
    @Autowired
    SerieService serieService;
    @Autowired
    GenreService genreService;
    @Autowired
    ChapterService chapterService;
    ViewService viewService;
    @GetMapping()
    @PreAuthorize("hasAuthority('view_movies') or hasRole('ADMIN')")
    public ResponseEntity<List<MovieAdmin>> getListMovie(){
        return new ResponseEntity<>(movieService.getAdminMovie(), HttpStatus.OK);
    }
    @PostMapping("/add")
    @PreAuthorize("hasAuthority('add_movie') or hasRole('ADMIN')")
    public ResponseEntity<String> addMovie(@ModelAttribute MovieAdd movieAdd) throws IOException {
        boolean existName = movieService.findByName(movieAdd.getName());
        if(existName) throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Tên phim đã tồn tại");
        Movie movie = MovieMapper.mapToMovie(movieAdd);
        Serie serie = serieService.findById(movieAdd.getSeries());
        List<Genre> genres = genreService.findGenresByList(movieAdd.getGenres());
        movie.setSerie(serie);
        movie.setGenres(genres);
        movie.setStatus(false);
        movieService.save(movie);
        String avatar = uploadService.uploadMovieAvt(movieAdd.getFile(),movie.getId());
        movie.setAvatarMovie(avatar);
        movie.setStatus(true);
        movieService.save(movie);
        return new ResponseEntity<>("Thêm thành công",HttpStatus.CREATED);
    }
    @PreAuthorize("hasAuthority('delete_movie') or hasRole('ADMIN')")
    @DeleteMapping("/delete/{id}")
    public ResponseEntity<String> deleteMovie(@PathVariable Long id) throws Exception {
        Movie movie = movieService.findById(id);
        if(movie == null) throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Phim không tồn tại, vui lòng thử lại!");
        movie.setStatus(false);
        movieService.save(movie);
        uploadService.deleteFolderMovie(uploadService.getMovieFolderById(movie.getId()));
        return new ResponseEntity<>("Xóa thành công!",HttpStatus.CREATED);
    }

    @PreAuthorize("hasAuthority('view_chapters') or hasRole('ADMIN')")
    @GetMapping("/{idMovie}/chapters")
    public ResponseEntity<List<ChapterDTO>> getMovieChapters(@PathVariable Long idMovie){
        List<ChapterDTO> chapterDTOS = chapterService.getMovieChapters(idMovie);
        return new ResponseEntity<>(new ArrayList<>(chapterDTOS),HttpStatus.OK);
    }
    @PreAuthorize("hasAuthority('add_chapter') or hasRole('ADMIN')")
    @PostMapping("/{idMovie}/chapters")
    public ResponseEntity<List<ChapterDTO>> addChapter(@PathVariable Long idMovie, @ModelAttribute ChapterRequest chapterAdd, BindingResult bindingResult) throws Exception {
        if (bindingResult.hasErrors()) {
            throw new ResponseStatusException(HttpStatus.NOT_ACCEPTABLE,"Dữ liệu không hợp lệ [ordinal] kiểu số, [link] kiểu ký tự ");
        }
        Movie movie = movieService.findById(idMovie);
        if(movie==null) throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Phim không tồn tại");

        boolean isExistOrdinal = false;
        int type = chapterAdd.getType();
        Chapter newChapter;
        List<ChapterDTO> response = new ArrayList<>();
        if(type==ChapterRequest.URL || type == ChapterRequest.VIDEO){
            isExistOrdinal =  chapterService.isExistOrdinal(idMovie,chapterAdd.getOrdinal());
            if(isExistOrdinal) throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Tập phim số "+chapterAdd.getOrdinal()+" này đã có");
            newChapter = new Chapter();
            newChapter.setOrdinal(chapterAdd.getOrdinal());
            newChapter.setMovie(movie);
            if(type == ChapterRequest.URL){
                newChapter.setLink(chapterAdd.getLink());
            }else{
                String url = uploadService.uploadChapter(chapterAdd.getVideo(),idMovie,chapterAdd.getOrdinal());
                newChapter.setLink(url);
            }
            chapterService.save(newChapter);
            response.add(ChapterMapper.mapToChapterDto(newChapter));
        }else if(type == ChapterRequest.EXCEL){
            Map<Integer, String> data = chapterAdd.getExcelData();
            for (Map.Entry<Integer, String> entry : data.entrySet()) {
                Integer ordinal = entry.getKey();
                String link = entry.getValue();
                isExistOrdinal =  chapterService.isExistOrdinal(idMovie,ordinal);
                if(isExistOrdinal){
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Tập phim số "+ordinal+" này đã có");
                }
                newChapter = new Chapter();
                newChapter.setMovie(movie);
                newChapter.setOrdinal(ordinal);
                newChapter.setLink(link);
                chapterService.save(newChapter);
                response.add(ChapterMapper.mapToChapterDto(newChapter));
            }
        }
        return new ResponseEntity<>(response,HttpStatus.CREATED);

    }
    @PreAuthorize("hasAuthority('edit_chapter') or hasRole('ADMIN')")
    @PutMapping("/{idMovie}/chapter/{idChapter}/edit")
    public ResponseEntity<ChapterDTO> editChapter(@PathVariable Long idMovie,@PathVariable Long idChapter,@RequestBody ChapterRequest chapterEdit){
        Chapter chapter = chapterService.findById(idChapter);
        if(chapter==null)  throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Tập không tồn tại!");
        if(chapterEdit.getOrdinal()!=chapter.getOrdinal()){
          boolean isExistOrdinal =  chapterService.isExistOrdinal(idMovie,idChapter,chapterEdit.getOrdinal());
          if(isExistOrdinal) throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Tập này đã tồn tại!");
        }
        chapter.setOrdinal(chapterEdit.getOrdinal());
        chapter.setLink(chapterEdit.getLink());
        chapter.setUpdateAt(new Date());
        chapterService.save(chapter);
        return new ResponseEntity<>(ChapterMapper.mapToChapterDto(chapter),HttpStatus.CREATED);
    }
    @PreAuthorize("hasAuthority('edit_chapter') or hasRole('ADMIN')")
    @PutMapping("/{idMovie}/chapter/{idChapter}/editFile")
    public ResponseEntity<ChapterDTO> editChapterFile(@PathVariable Long idMovie, @PathVariable Long idChapter, @ModelAttribute ChapterRequest chapterEdit) throws Exception {
        Chapter chapter = chapterService.findById(idChapter);
        if(chapter==null) throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Tập không tồn tại!");
        if(chapterEdit.getOrdinal()!=chapter.getOrdinal()){
            boolean isExistOrdinal =  chapterService.isExistOrdinal(idMovie,idChapter,chapterEdit.getOrdinal());
            if(isExistOrdinal) throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Tập này đã tồn tại!");
        }
        String newLink = uploadService.uploadChapter(chapterEdit.getVideo(),idMovie,chapter.getOrdinal());
        chapter.setUpdateAt(new Date());
        chapter.setLink(newLink);
        chapterService.save(chapter);
        return new ResponseEntity<>(ChapterMapper.mapToChapterDto(chapter),HttpStatus.CREATED);
    }
    @PreAuthorize("hasAuthority('delete_chapter') or hasRole('ADMIN')")
    @DeleteMapping("/{idMovie}/chapter/{idChapter}")
    public ResponseEntity<String> deleteChapter(@PathVariable Long idMovie,@PathVariable Long idChapter) throws Exception {
        Chapter chapter = chapterService.findById(idChapter);
        chapter.setStatus(false);
        uploadService.deleteChapter(idMovie,chapter.getOrdinal());
        chapterService.save(chapter);
        return new ResponseEntity<>("Xóa thành công",HttpStatus.CREATED);
    }
    @PutMapping("/{idMovie}")
    @PreAuthorize("hasAuthority('edit_movie') or hasRole('ADMIN')")
    public ResponseEntity<String> editMovie(@PathVariable Long idMovie,@ModelAttribute MovieAdd movieAdd) throws IOException {
        boolean existName = movieService.findByNameNotThis(idMovie, movieAdd.getName());
        if (existName) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Tên phim đã tồn tại");
        Movie movie = movieService.findById(idMovie);
        Serie serie = serieService.findById(movieAdd.getSeries());
        List<Genre> genres = genreService.findGenresByList(movieAdd.getGenres());
        movie.setName(movieAdd.getName());
        movie.setTotalChapters(movieAdd.getTotalChapters());
        movie.setVietnameseDescriptions(movieAdd.getVietnameseDescriptions());
        movie.setEnglishDescriptions(movieAdd.getEnglishDescriptions());
        movie.setProducer(movieAdd.getProducer());
        movie.setSerie(serie);
        movie.setTrailer(movieAdd.getTrailer());
        movie.setGenres(genres);
        movie.setSeriesDescriptions(movieAdd.getSeriesDescriptions());
        movie.setUpdateAt(new Date());

        String avatar = uploadService.uploadMovieAvt(movieAdd.getFile(), movie.getId());
        movie.setAvatarMovie(avatar);
        movieService.save(movie);
        return new ResponseEntity<>("Sửa thành công", HttpStatus.CREATED);
    }
    @GetMapping("/viewed/month/top5")
    public  ResponseEntity<List<Movie>>getTop5MovieViewedByMonth(){
        return  ResponseEntity.ok(viewService.GetTop5MovieViewedByMonth());
    }
    @GetMapping("/viewed/year/top5")
    public  ResponseEntity<List<Movie>>getTop5MovieViewedByYear(){
        return  ResponseEntity.ok(viewService.GetTop5MovieViewedByYear());
    }
}

