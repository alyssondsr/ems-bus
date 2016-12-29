import * as _ from "lodash";
import {Pipe, PipeTransform} from "@angular/core";
import { DataTableModule } from 'angular2-datatable';

@Pipe({
    name: "dataFilter"
})
export class DataTableFilterPipe implements PipeTransform {

    transform(array: any[], query: string): any {
        if (query) {
            return _.filter(array, row=>row.name.indexOf(query) > -1);
        }
        return array;
    }
}
